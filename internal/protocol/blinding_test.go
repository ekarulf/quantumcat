package protocol

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ekarulf/quantumcat/internal/crypto/provider/software"
)

func TestPeerTagKnownAnswer(t *testing.T) {
	id := ID([]byte("test-public-key"))
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	tag := peerTag(id, nonce)
	if got, want := hex.EncodeToString(tag[:]), "eb954a8e5e866e85291603ddacb52e16c0ca65af6ead943f9f88b93c1c72f8d9"; got != want {
		t.Fatalf("peer tag = %s, want %s", got, want)
	}
}

func TestPeerTagDeterminismAndUnlinkability(t *testing.T) {
	first, second := ID([]byte("peer-one")), ID([]byte("peer-two"))
	n1, n2 := make([]byte, 32), make([]byte, 32)
	rand.Read(n1)
	rand.Read(n2)
	if peerTag(first, n1) != peerTag(first, n1) {
		t.Fatal("tag is not a deterministic function of PeerID and nonce")
	}
	if peerTag(first, n1) == peerTag(first, n2) {
		t.Fatal("one identity produced the same tag under two nonces")
	}
	if peerTag(first, n1) == peerTag(second, n1) {
		t.Fatal("two identities collided under one nonce")
	}
}

// The wire pseudonym is worthless if the stable identifier it replaces still
// appears somewhere in the packet.
func TestClientHelloOmitsRawPeerID(t *testing.T) {
	_, c, hello, _, _ := fixture(t)
	pub, err := c.identity.PublicKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id := ID(pub)
	if bytes.Contains(hello, id[:]) {
		t.Fatal("ClientHello still transmits the stable client PeerID")
	}
	if bytes.Contains(hello, pub) {
		t.Fatal("ClientHello transmits the client ML-DSA public key")
	}
	tag := peerTag(id, c.hello[96:128])
	if !bytes.Equal(c.hello[:32], tag[:]) {
		t.Fatal("ClientHello does not carry the nonce-blinded peer tag")
	}
}

// Blinding must not change the payload sizes frozen by version 1.
func TestBlindingDoesNotChangeWireSize(t *testing.T) {
	_, _, hello, _, _ := fixture(t)
	if helloSize != 32*6+8+1568 {
		t.Fatalf("unsigned hello = %d bytes, want %d", helloSize, 32*6+8+1568)
	}
	if got, want := len(hello), 8+helloSize+mldsa.MLDSA87SignatureSize; got != want {
		t.Fatalf("ClientHello frame = %d bytes, want %d", got, want)
	}
	if len(hello) != 8+6395 {
		t.Fatalf("ClientHello payload = %d bytes, want 6395", len(hello)-8)
	}
}

// decoys returns authorized entries that pad the server's tag scan so a match
// has to be selected rather than assumed. Their tags are uniformly random
// relative to the real one, so they establish that the scan finds the right
// entry among many; they cannot detect a truncated comparison.
// TestResolveComparesEveryTagByte covers that separately.
func decoys(t *testing.T, n int) map[PeerID][]byte {
	t.Helper()
	set := map[PeerID][]byte{}
	for range n {
		pub := make([]byte, mldsa.MLDSA87PublicKeySize)
		if _, err := rand.Read(pub); err != nil {
			t.Fatal(err)
		}
		set[ID(pub)] = pub
	}
	return set
}

// A prefix-only or truncated tag comparison would still match a tag that
// differs only in its last byte. Random decoys cannot surface that, so flip the
// final byte of an otherwise correct tag and require resolution to reject it.
func TestResolveComparesEveryTagByte(t *testing.T) {
	s, c, _, _, _ := fixture(t)
	pub, err := c.identity.PublicKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	nonce := c.hello[96:128]
	good := peerTag(ID(pub), nonce)
	if id, key := s.resolve(good[:], nonce); id != ID(pub) || !bytes.Equal(key, pub) {
		t.Fatal("resolve rejected the correct tag")
	}
	near := good
	near[31] ^= 1
	if id, key := s.resolve(near[:], nonce); len(key) != 0 || id != (PeerID{}) {
		t.Fatal("resolve matched a tag differing only in its final byte")
	}
}

// Two genuinely authorized identities must each resolve to their own public key.
// The decoys elsewhere are random bytes rather than real ML-DSA keys, so a
// mis-resolution there shows up only as a signature failure, which looks the
// same as any other rejection.
func TestResolutionDistinguishesTwoRealIdentities(t *testing.T) {
	s, first, hello, src, now := fixture(t)
	ctx := context.Background()
	other, err := software.Generate()
	if err != nil {
		t.Fatal(err)
	}
	firstPub, err := first.identity.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := other.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.Authorized = func(yield func(PeerID, []byte) bool) {
		if !yield(ID(firstPub), firstPub) {
			return
		}
		yield(ID(otherPub), otherPub)
	}
	otherSrc := [32]byte{7}
	otherClient, otherHello, err := NewClient(ctx, other, software.NewKEM, first.serverPublic, Keys{WG: otherSrc, Disco: [32]byte{2}}, first.keys, now)
	if err != nil {
		t.Fatal(err)
	}
	defer otherClient.Close()
	// Each tag must select its own signer, not merely some authorized peer.
	if id, key := s.resolve(hello[8:40], hello[8+96:8+128]); id != ID(firstPub) || !bytes.Equal(key, firstPub) {
		t.Fatal("first identity's tag did not resolve to its own key")
	}
	if id, key := s.resolve(otherHello[8:40], otherHello[8+96:8+128]); id != ID(otherPub) || !bytes.Equal(key, otherPub) {
		t.Fatal("second identity's tag did not resolve to its own key")
	}
	if reply, _ := s.Handle(ctx, src, hello, now); len(reply) == 0 {
		t.Fatal("first identity rejected")
	}
	if reply, _ := s.Handle(ctx, otherSrc, otherHello, now); len(reply) == 0 {
		t.Fatal("second identity rejected")
	}
}

// A server configured with no authorized set must drop hellos, not panic on the
// bootstrap path.
func TestNilAuthorizedSetDropsWithoutPanic(t *testing.T) {
	s, _, hello, src, now := fixture(t)
	s.Authorized = nil
	if reply, session := s.Handle(context.Background(), src, hello, now); reply != nil || session != nil {
		t.Fatal("nil authorized set accepted a hello")
	}
	if pub := Lookup(nil, PeerID{}); pub != nil {
		t.Fatal("Lookup on a nil iterator returned a key")
	}
}

// Blinding is what lets a hello from an unknown source occupy a per-source rate
// entry before its tag is resolved, so the 4096-entry cap with oldest-first
// eviction is the mechanism that keeps the new exposure finite. Exercise that
// cap on the real path rather than only unit-testing evictOldest.
func TestSourceRateTableStaysBoundedForUnknownTags(t *testing.T) {
	s, _, hello, src, now := fixture(t)
	ctx := context.Background()
	if reply, _ := s.Handle(ctx, src, hello, now); len(reply) == 0 {
		t.Fatal("initial handshake rejected")
	}
	// Fill to the cap with entries older than the genuine sender's, so eviction
	// has an unambiguous oldest victim. Keep the whole spread inside one second:
	// Handle prunes idle entries older than that before it consults the cap.
	for i := range 4095 {
		var key [32]byte
		binary.BigEndian.PutUint32(key[:], uint32(i))
		s.limits[key] = bucket{start: now.Add(-time.Duration(i+1) * 200 * time.Microsecond), tokens: 4}
	}
	if len(s.limits) != 4096 {
		t.Fatalf("setup: source table has %d entries, want 4096", len(s.limits))
	}
	var oldest [32]byte
	binary.BigEndian.PutUint32(oldest[:], 4094)
	// An unresolvable tag from a source with no entry: the entry is charged
	// before resolution, so this is the case the cap has to absorb.
	unknown := append([]byte(nil), hello...)
	if _, err := rand.Read(unknown[8:40]); err != nil {
		t.Fatal(err)
	}
	fresh := [32]byte{0xAB}
	copy(unknown[8+32:8+64], fresh[:])
	if reply, session := s.Handle(ctx, fresh, unknown, now); reply != nil || session != nil {
		t.Fatal("accepted an unresolvable tag")
	}
	if len(s.limits) != 4096 {
		t.Fatalf("source table holds %d entries, want it pinned at 4096", len(s.limits))
	}
	if _, exists := s.limits[fresh]; !exists {
		t.Fatal("unknown source was not charged a rate entry")
	}
	if _, exists := s.limits[oldest]; exists {
		t.Fatal("eviction did not remove the oldest entry")
	}
	if _, exists := s.limits[src]; !exists {
		t.Fatal("eviction discarded the active sender's newer entry")
	}
}

func TestServerResolvesTagAmongManyAuthorizedPeers(t *testing.T) {
	s, c, hello, src, now := fixture(t)
	ctx := context.Background()
	pub, err := c.identity.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	set := decoys(t, 16)
	set[ID(pub)] = pub
	s.Authorized = func(yield func(PeerID, []byte) bool) {
		for id, key := range set {
			if !yield(id, key) {
				return
			}
		}
	}
	reply, session := s.Handle(ctx, src, hello, now)
	if len(reply) == 0 || session != nil {
		t.Fatal("server failed to resolve a blinded tag against its authorized set")
	}
	psk, finish, err := c.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	ack, session := s.Handle(ctx, src, finish, now.Add(time.Second))
	if session == nil || session.PSK != psk || !c.Accepted(ack) {
		t.Fatal("handshake did not complete through a blinded tag")
	}
	// Installed state must carry the real identity, never the wire pseudonym.
	if session.Peer != ID(pub) {
		t.Fatal("session identity is not the resolved PeerID")
	}
	if session.Peer == PeerID(c.hello[:32]) {
		t.Fatal("session identity is the blinded tag")
	}
	session.Installed(true)
}

// An unresolvable tag must be dropped before any post-quantum work: no reply,
// no encapsulation, no pending or replay state, and no charge to an identity
// quota. It must still pay the source rate limit.
func TestUnknownTagCostsNothingBeyondSourceLimit(t *testing.T) {
	s, c, hello, src, now := fixture(t)
	ctx := context.Background()
	unknown := append([]byte(nil), hello...)
	if _, err := rand.Read(unknown[8:40]); err != nil {
		t.Fatal(err)
	}
	// Only the first four reach resolution; the per-source bucket drops the rest
	// at a fixed `now`. That is the point: the flood is bounded before the scan.
	for range 100 {
		if reply, session := s.Handle(ctx, src, unknown, now); reply != nil || session != nil {
			t.Fatal("accepted an unresolvable peer tag")
		}
	}
	if len(s.pending) != 0 || len(s.replay) != 0 {
		t.Fatalf("allocated state for an unknown tag: pending=%d replay=%d", len(s.pending), len(s.replay))
	}
	if len(s.peerLimits) != 0 {
		t.Fatal("charged an authenticated identity quota for an unknown tag")
	}
	if !s.global.start.IsZero() {
		t.Fatal("unknown tag consumed the shared verification budget")
	}
	if bucket, ok := s.limits[src]; !ok || bucket.tokens > 0 {
		t.Fatalf("unknown tag bypassed the source rate limit: %+v", bucket)
	}
	// The rate entry is keyed on the source, so one sender's flood cannot starve
	// another's handshake. (The scan's position in the order is pinned by the
	// s.global assertion above, not by this check.)
	other := [32]byte{9}
	honest, fresh, err := NewClient(ctx, c.identity, software.NewKEM, c.serverPublic, Keys{WG: other, Disco: [32]byte{1}}, c.keys, now)
	if err != nil {
		t.Fatal(err)
	}
	defer honest.Close()
	if reply, _ := s.Handle(ctx, other, fresh, now); len(reply) == 0 {
		t.Fatal("unknown-tag flood blocked a legitimate handshake from another source")
	}
}

// Resolution selects a public key; it never substitutes for authentication. A
// hello whose transmitted tag resolves but whose signature covers different
// bytes must fail, which also proves the tag itself is inside the signed hello.
func TestPeerTagIsSignatureBound(t *testing.T) {
	s, c, hello, src, now := fixture(t)
	ctx := context.Background()
	pub, err := c.identity.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := ID(pub)
	// Sign the pre-blinding layout, which carried the raw PeerID in this field.
	unsigned := append([]byte(nil), c.hello...)
	copy(unsigned, id[:])
	sig, err := c.identity.Sign(ctx, ClientContext, frame(ClientHello, unsigned))
	if err != nil {
		t.Fatal(err)
	}
	forged := frame(ClientHello, join(c.hello, sig))
	if reply, session := s.Handle(ctx, src, forged, now); reply != nil || session != nil {
		t.Fatal("transmitted peer tag is not covered by the client signature")
	}
	if s.global.start.IsZero() {
		t.Fatal("resolvable tag skipped the verification budget")
	}
	if len(s.peerLimits) != 0 {
		t.Fatal("invalid signature charged the resolved identity's quota")
	}
	if reply, _ := s.Handle(ctx, src, hello, now); len(reply) == 0 {
		t.Fatal("forgery attempt blocked the genuine hello")
	}
}

// Every signed field must fail without a fresh signature, but which check does
// the rejecting matters as much as the rejection itself: a mutation caught by an
// earlier, cheaper check never exercises signature coverage at all. Each case
// therefore pins the stage it reaches, using the shared verification budget as
// the observable marker for "got as far as ML-DSA".
func TestMutatedHelloFieldsFailWithoutResigning(t *testing.T) {
	for name, c := range map[string]struct {
		offset   int
		verified bool
	}{
		// Mutating the tag, or the nonce that keys it, changes the tag the server
		// expects, so these are dropped at resolution before the budget is spent.
		"peer-tag": {offset: 0},
		"nonce":    {offset: 96},
		// These survive the cheap checks and resolution, so only the signature can
		// catch them.
		"wg-public": {offset: 32, verified: true},
		"disco":     {offset: 64, verified: true},
		"kem":       {offset: 200, verified: true},
		// Byte 199 is the timestamp's least significant byte, so this shifts the
		// stamp by one second and stays inside the ±120s window. Mutating byte 192
		// instead would move it billions of years out, and the freshness check
		// would reject it before the signature was ever considered.
		"timestamp": {offset: 199, verified: true},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, hello, src, now := fixture(t)
			hello[8+c.offset] ^= 1
			// The WG field is also the transport source binding; keep them equal so
			// the mutation is tested by the signature rather than the source check.
			if c.offset == 32 {
				src[0] ^= 1
			}
			if reply, session := s.Handle(context.Background(), src, hello, now); reply != nil || session != nil {
				t.Fatalf("accepted %s mutation without a fresh signature", name)
			}
			if len(s.pending) != 0 {
				t.Fatal("mutated hello allocated pending state")
			}
			if reached := !s.global.start.IsZero(); reached != c.verified {
				t.Fatalf("%s mutation reached ML-DSA verification = %t, want %t", name, reached, c.verified)
			}
		})
	}
}

// Revoking an identity removes it from the authorized set, so its tags stop
// resolving even though they remain well formed.
func TestRevokedIdentityTagNoLongerResolves(t *testing.T) {
	s, c, hello, src, now := fixture(t)
	ctx := context.Background()
	pub, err := c.identity.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reply, _ := s.Handle(ctx, src, hello, now); len(reply) == 0 {
		t.Fatal("authorized tag rejected")
	}
	spent := s.peerLimits[[32]byte(ID(pub))]
	set := decoys(t, 4)
	s.Authorized = func(yield func(PeerID, []byte) bool) {
		for id, key := range set {
			if !yield(id, key) {
				return
			}
		}
	}
	next, renewed, err := NewClient(ctx, c.identity, software.NewKEM, c.serverPublic, Keys{WG: src, Disco: [32]byte{1}}, c.keys, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if reply, session := s.Handle(ctx, src, renewed, now.Add(time.Second)); reply != nil || session != nil {
		t.Fatal("revoked identity still resolved its blinded tag")
	}
	if s.peerLimits[[32]byte(ID(pub))] != spent {
		t.Fatal("revoked identity charged a quota")
	}
}

// Renewal reuses the WireGuard and discovery keys but draws a fresh nonce, so
// the tag changes while the authenticated owner and the lease it replaces do
// not.
func TestRenewalChangesTagButNotOwner(t *testing.T) {
	s, first, hello, src, now := fixture(t)
	ctx := context.Background()
	pub, err := first.identity.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reply, _ := s.Handle(ctx, src, hello, now)
	psk, finish, err := first.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	_, session := s.Handle(ctx, src, finish, now)
	if session == nil {
		t.Fatal("initial handshake did not install")
	}
	session.Installed(true)
	disco := Keys{WG: src, Disco: [32]byte(hello[8+64 : 8+96])}
	next, renewal, err := NewClient(ctx, first.identity, software.NewKEM, first.serverPublic, disco, first.keys, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if bytes.Equal(renewal[8:40], hello[8:40]) {
		t.Fatal("renewal reused the previous blinded tag")
	}
	if bytes.Equal(renewal[8+96:8+128], hello[8+96:8+128]) {
		t.Fatal("renewal reused the previous nonce")
	}
	reply, _ = s.Handle(ctx, src, renewal, now.Add(time.Second))
	if len(reply) == 0 {
		t.Fatal("renewal rejected")
	}
	renewedPSK, renewalFinish, err := next.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	_, renewed := s.Handle(ctx, src, renewalFinish, now.Add(2*time.Second))
	if renewed == nil {
		t.Fatal("renewal did not install")
	}
	if renewed.Peer != ID(pub) {
		t.Fatal("renewal changed the authenticated owner")
	}
	if renewed.PSK != renewedPSK || renewedPSK == psk {
		t.Fatal("renewal did not replace the PSK")
	}
	if renewed.Keys != disco {
		t.Fatal("renewal changed the transport keys")
	}
	renewed.Installed(true)
}
