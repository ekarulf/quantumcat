package protocol

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ekarulf/quantumcat/internal/crypto/provider"
	"github.com/ekarulf/quantumcat/internal/crypto/provider/software"
)

func fixture(t *testing.T) (*Server, *Client, []byte, [32]byte, time.Time) {
	t.Helper()
	ctx := context.Background()
	si, err := software.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ci, err := software.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := si.PublicKey(ctx)
	cp, _ := ci.PublicKey(ctx)
	var local, remote Keys
	rand.Read(local.WG[:])
	rand.Read(local.Disco[:])
	rand.Read(remote.WG[:])
	rand.Read(remote.Disco[:])
	now := time.Now().Truncate(time.Second)
	s := &Server{Identity: si, Public: sp, Keys: remote, Authorized: func(yield func(PeerID, []byte) bool) { yield(ID(cp), cp) }}
	c, hello, err := NewClient(ctx, ci, software.NewKEM, sp, local, remote, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return s, c, hello, local.WG, now
}
func TestHandshakeAndRetransmission(t *testing.T) {
	s, c, hello, src, now := fixture(t)
	ctx := context.Background()
	reply, session := s.Handle(ctx, src, hello, now)
	if len(reply) == 0 || session != nil {
		t.Fatal("peer installed before confirmation")
	}
	duplicate, session := s.Handle(ctx, src, hello, now.Add(time.Second))
	if session != nil || !bytes.Equal(reply, duplicate) {
		t.Fatal("retransmission must use cached encapsulation")
	}
	psk, finish, err := c.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	ack, session := s.Handle(ctx, src, finish, now.Add(2*time.Second))
	if session == nil || session.PSK != psk || psk == [32]byte{} || !c.Accepted(ack) {
		t.Fatal("key confirmation mismatch")
	}
	session.Installed(true)
	ack2, session := s.Handle(ctx, src, finish, now.Add(3*time.Second))
	if session != nil || !bytes.Equal(ack, ack2) {
		t.Fatal("finish replay must not reinstall session")
	}
	if _, err = c.kem.Decapsulate(ctx, make([]byte, 1568)); err == nil {
		t.Fatal("ephemeral key survived completion")
	}
}

func TestFailedInstallationReturnsAuthenticatedRejection(t *testing.T) {
	s, c, hello, src, now := fixture(t)
	ctx := context.Background()
	reply, _ := s.Handle(ctx, src, hello, now)
	_, finish, err := c.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	_, session := s.Handle(ctx, src, finish, now)
	if session == nil {
		t.Fatal("missing installation candidate")
	}
	if ack, next := s.Handle(ctx, src, finish, now); ack != nil || next != nil {
		t.Fatal("acknowledged installation before it completed")
	}
	session.Installed(false)
	session.Installed(true) // A failure cannot later be committed.
	rejection, next := s.Handle(ctx, src, finish, now)
	if next != nil || !c.Rejected(rejection) || c.Accepted(rejection) {
		t.Fatal("installation failure was not authenticated as a rejection")
	}
	p := s.pending[[hashSize]byte(finish[8:8+hashSize])]
	if p == nil || !p.rejected || p.session.PSK != [32]byte{} || p.state.Root != [hashSize]byte{} {
		t.Fatal("rejected candidate retained installation key material")
	}
}

func TestInvalidSignaturesDoNotChargeIdentityQuota(t *testing.T) {
	s, _, hello, src, now := fixture(t)
	ctx := context.Background()
	forged := append([]byte(nil), hello...)
	attacker := src
	attacker[0] ^= 1
	copy(forged[40:72], attacker[:]) // Source/WG match, but signature is invalid.
	for range 100 {
		if reply, session := s.Handle(ctx, attacker, forged, now); reply != nil || session != nil {
			t.Fatal("accepted invalid signature")
		}
	}
	if len(s.peerLimits) != 0 {
		t.Fatal("charged unauthenticated claimed identity")
	}
	if s.global.tokens != 60 {
		t.Fatalf("source bypassed verification quota: %v remaining", s.global.tokens)
	}
	if reply, _ := s.Handle(ctx, src, hello, now); len(reply) == 0 {
		t.Fatal("invalid sender prevented legitimate authentication")
	}
}
func TestRejectClientTampering(t *testing.T) {
	for _, offset := range []int{0, 4, 5, 6, 8, 40, 72, 104, 136, 168, 200, 208, 1800, 6000} {
		t.Run(string(rune('a'+offset%26))+"/"+time.Duration(offset).String(), func(t *testing.T) {
			s, _, hello, src, now := fixture(t)
			hello[offset] ^= 1
			if reply, session := s.Handle(context.Background(), src, hello, now); reply != nil || session != nil {
				t.Fatal("accepted tampered hello")
			}
		})
	}
}
func TestRejectServerTampering(t *testing.T) {
	for _, offset := range []int{0, 4, 8, 40, 72, 104, 136, 1800, 6300} {
		s, c, hello, src, now := fixture(t)
		reply, _ := s.Handle(context.Background(), src, hello, now)
		reply[offset] ^= 1
		if _, _, err := c.Complete(context.Background(), reply); err == nil {
			t.Fatalf("accepted tampering at %d", offset)
		}
	}
}
func TestFreshnessSourceRevocationAndExpiry(t *testing.T) {
	for _, test := range []string{"stale", "future", "source", "unknown", "revoked", "expired", "bad-finish"} {
		t.Run(test, func(t *testing.T) {
			s, c, hello, src, now := fixture(t)
			ctx := context.Background()
			switch test {
			case "stale":
				now = now.Add(121 * time.Second)
			case "future":
				now = now.Add(-121 * time.Second)
			case "source":
				src[0] ^= 1
			case "unknown":
				s.Authorized = func(func(PeerID, []byte) bool) {}
			}
			reply, session := s.Handle(ctx, src, hello, now)
			if test == "stale" || test == "future" || test == "source" || test == "unknown" {
				if reply != nil || session != nil {
					t.Fatal("unexpected authentication")
				}
				return
			}
			_, finish, err := c.Complete(ctx, reply)
			if err != nil {
				t.Fatal(err)
			}
			switch test {
			case "revoked":
				s.Authorized = func(func(PeerID, []byte) bool) {}
			case "expired":
				now = now.Add(31 * time.Second)
			case "bad-finish":
				finish[len(finish)-1] ^= 1
			}
			if _, session = s.Handle(ctx, src, finish, now); session != nil {
				t.Fatal("invalid finish installed peer")
			}
		})
	}
}
func TestIndependentSessions(t *testing.T) {
	s, c, h, src, now := fixture(t)
	ctx := context.Background()
	reply, _ := s.Handle(ctx, src, h, now)
	first, _, err := c.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	next, h, err := NewClient(ctx, c.identity, software.NewKEM, c.serverPublic, Keys{WG: src, Disco: [32]byte{1}}, c.keys, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	reply, _ = s.Handle(ctx, src, h, now.Add(time.Second))
	second, _, err := next.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("connections reused PSK")
	}
}
func FuzzParse(f *testing.F) {
	f.Add([]byte("QCAT"))
	f.Add(frame(ClientFinish, make([]byte, hashSize+proofSize)))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = Parse(b) })
}

func TestValidFrame(t *testing.T) {
	valid := frame(ClientFinish, make([]byte, hashSize+proofSize))
	if !ValidFrame(valid) {
		t.Fatal("valid frame rejected")
	}
	for name, mutate := range map[string]func([]byte){
		"version": func(b []byte) { b[4]++ },
		"kind":    func(b []byte) { b[5] = 99 },
		"length":  func(b []byte) { b[7]++ },
	} {
		t.Run(name, func(t *testing.T) {
			packet := append([]byte(nil), valid...)
			mutate(packet)
			if ValidFrame(packet) {
				t.Fatal("malformed frame accepted")
			}
		})
	}
	if ValidFrame(append(valid, 0)) {
		t.Fatal("wrong-sized frame accepted")
	}
}

func TestVersionOneSHA384Sizes(t *testing.T) {
	if Version != 1 || hashSize != sha512.Size384 || proofSize != sha512.Size384 {
		t.Fatalf("unexpected suite constants: version=%d hash=%d proof=%d", Version, hashSize, proofSize)
	}
	if serverSize != 6371 || hashSize+proofSize != 96 {
		t.Fatalf("unexpected payload sizes: server=%d finish=%d", serverSize, hashSize+proofSize)
	}
	if helloSize != 1768 || transcriptSize != 3483 || transcriptSize <= hashSize {
		t.Fatalf("unexpected transcript size: %d", transcriptSize)
	}
}

func TestPeerIDKnownAnswer(t *testing.T) {
	id := ID([]byte("test-public-key"))
	if got, want := hex.EncodeToString(id[:]), "6df04077360795c911785203700a30d0af82120bdc2f9d397812b86a3d6ed117"; got != want {
		t.Fatalf("PeerID = %s, want %s", got, want)
	}
}

func TestTranscriptCoversCompleteHello(t *testing.T) {
	hello := make([]byte, helloSize)
	server := PeerID{1}
	keys := Keys{WG: [32]byte{2}, Disco: [32]byte{3}}
	nonce := make([]byte, 32)
	ct := make([]byte, mlkem.CiphertextSize1024)
	_, want := transcript(hello, server, keys, nonce, ct)
	for i := range hello {
		hello[i] ^= 1
		if _, got := transcript(hello, server, keys, nonce, ct); got == want {
			t.Fatalf("hello byte %d is not transcript-bound", i)
		}
		hello[i] ^= 1
	}
}

type recordingIdentity struct {
	provider.Identity
	label string
	msg   []byte
}

func (r *recordingIdentity) Sign(ctx context.Context, label string, msg []byte) ([]byte, error) {
	r.label, r.msg = label, append([]byte(nil), msg...)
	return r.Identity.Sign(ctx, label, msg)
}

func TestServerSignsCanonicalTranscriptNotDigest(t *testing.T) {
	s, c, hello, src, now := fixture(t)
	ctx := context.Background()
	recorder := &recordingIdentity{Identity: s.Identity}
	s.Identity = recorder
	reply, _ := s.Handle(ctx, src, hello, now)
	if len(reply) == 0 {
		t.Fatal("server rejected a valid hello")
	}
	if recorder.label != ServerContext {
		t.Fatalf("signed under context %q, want %q", recorder.label, ServerContext)
	}
	_, b, err := Parse(reply)
	if err != nil {
		t.Fatal(err)
	}
	ct := b[128 : 128+mlkem.CiphertextSize1024]
	tb, hash := transcript(c.hello, c.server, c.keys, b[96:128], ct)
	if !bytes.Equal(recorder.msg, tb) {
		t.Fatal("signature does not cover the canonical transcript")
	}
	if len(recorder.msg) != transcriptSize {
		t.Fatalf("signed %d bytes, want %d", len(recorder.msg), transcriptSize)
	}
	if bytes.Equal(recorder.msg, hash[:]) {
		t.Fatal("server pre-hashed the transcript before signing")
	}
	if !bytes.HasSuffix(recorder.msg, c.hello) {
		t.Fatal("signed transcript does not end with the complete hello")
	}
}

func TestClientRejectsDigestOnlyServerSignature(t *testing.T) {
	s, c, hello, src, now := fixture(t)
	ctx := context.Background()
	reply, _ := s.Handle(ctx, src, hello, now)
	if len(reply) == 0 {
		t.Fatal("server rejected a valid hello")
	}
	_, b, err := Parse(reply)
	if err != nil {
		t.Fatal(err)
	}
	ct := b[128 : 128+mlkem.CiphertextSize1024]
	_, hash := transcript(c.hello, c.server, c.keys, b[96:128], ct)
	legacy, err := s.Identity.Sign(ctx, ServerContext, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte(nil), reply...)
	copy(forged[8+128+mlkem.CiphertextSize1024:], legacy)
	if _, _, err := c.Complete(ctx, forged); err == nil {
		t.Fatal("client accepted a signature over the digest alone")
	}
}

func TestDeriveKnownAnswer(t *testing.T) {
	ss := make([]byte, 32)
	var hash [hashSize]byte
	for i := range ss {
		ss[i] = byte(i)
	}
	for i := range hash {
		hash[i] = byte(0x80 + i)
	}
	next, psk, confirmation, err := derive(State{}, 0, ss, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !next.valid || next.Epoch != 0 || next.Transcript != hash {
		t.Fatal("initial root state was not derived")
	}
	for name, test := range map[string]struct {
		got  []byte
		want string
	}{
		"root":         {next.Root[:], "bd22b207298b1a9279e30b1505bd0bb7a92183eefdf4cc719d46e47b74f2b10c8aa31c67be86b458e2bddb1e2f69c36b"},
		"psk":          {psk[:], "2eecdd4154c601037c071164dbb0b7cd60aa2715c731bc54d18b69e6ade91578"},
		"confirmation": {confirmation[:], "265032b01c15dca6d531597c85084db1fea7dc9bba44757f5d37835e5c848134"},
	} {
		if encoded := hex.EncodeToString(test.got); encoded != test.want {
			t.Fatalf("%s = %s, want %s", name, encoded, test.want)
		}
	}
	secondSS := make([]byte, 32)
	var secondHash [hashSize]byte
	for i := range secondSS {
		secondSS[i] = byte(32 + i)
	}
	for i := range secondHash {
		secondHash[i] = byte(0xc0 + i)
	}
	second, secondPSK, secondConfirmation, err := derive(next, 1, secondSS, secondHash)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		got  []byte
		want string
	}{
		"second root":         {second.Root[:], "6c90e54eb8d37f25661dcf002b07e6b2311f72cfca94d3f788b5fd931a8598f8a1761dabb255840491f837624a1e0303"},
		"second psk":          {secondPSK[:], "e8feaa16e685c40b9df0de80e69c72ae6f6274eeffe0e164e46e916432cbc7a9"},
		"second confirmation": {secondConfirmation[:], "ae33cd87224ce67c8bfb0e1222550e9912b550eb5151ee1fe5ae2a5dcd2138f2"},
	} {
		if encoded := hex.EncodeToString(test.got); encoded != test.want {
			t.Fatalf("%s = %s, want %s", name, encoded, test.want)
		}
	}
}

func TestRenewalRootBindsEveryInput(t *testing.T) {
	ss := bytes.Repeat([]byte{1}, 32)
	hash := [hashSize]byte{2}
	parent := State{Epoch: 7, Transcript: [hashSize]byte{3}, Root: [hashSize]byte{4}, valid: true}
	epoch := uint64(8)
	want, wantPSK, _, err := derive(parent, epoch, ss, hash)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*State, *uint64, []byte, *[hashSize]byte){
		"previous root":       func(s *State, _ *uint64, _ []byte, _ *[hashSize]byte) { s.Root[0]++ },
		"previous transcript": func(s *State, _ *uint64, _ []byte, _ *[hashSize]byte) { s.Transcript[0]++ },
		"epoch":               func(_ *State, e *uint64, _ []byte, _ *[hashSize]byte) { *e++ },
		"shared secret":       func(_ *State, _ *uint64, ss []byte, _ *[hashSize]byte) { ss[0]++ },
		"new transcript":      func(_ *State, _ *uint64, _ []byte, h *[hashSize]byte) { h[0]++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changedParent, changedEpoch, changedSS, changedHash := parent, epoch, append([]byte(nil), ss...), hash
			mutate(&changedParent, &changedEpoch, changedSS, &changedHash)
			got, gotPSK, _, err := derive(changedParent, changedEpoch, changedSS, changedHash)
			if err != nil {
				t.Fatal(err)
			}
			if got.Root == want.Root || gotPSK == wantPSK {
				t.Fatalf("changing %s did not change both root and PSK", name)
			}
		})
	}
}

func TestRenewalRatchetBindsParentAndEpoch(t *testing.T) {
	s, first, hello, src, now := fixture(t)
	ctx := context.Background()
	reply, _ := s.Handle(ctx, src, hello, now)
	_, finish, err := first.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	ack, installed := s.Handle(ctx, src, finish, now)
	if installed == nil || !first.Accepted(ack) {
		t.Fatal("initial handshake did not commit")
	}
	installed.Installed(true)

	// A renewal carrying the committed state advances the ratchet exactly once.
	local := Keys{WG: src, Disco: [32]byte(first.hello[clientDiscoOffset : clientDiscoOffset+32])}
	renewal, renewedHello, err := NewClientWithState(ctx, first.identity, software.NewKEM, first.serverPublic, local, first.keys, first.State(), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer renewal.Close()
	if got := binary.BigEndian.Uint64(renewedHello[8+epochOffset : 8+epochOffset+8]); got != 1 {
		t.Fatalf("renewal epoch=%d, want 1", got)
	}
	if reply, session := s.Handle(ctx, src, renewedHello, now.Add(time.Second)); len(reply) == 0 || session != nil {
		t.Fatal("valid renewal rejected")
	}

	// A zero-state client cannot reset the same node to epoch zero, and a valid
	// state cannot skip directly to a different parent transcript.
	stale, staleHello, err := NewClient(ctx, first.identity, software.NewKEM, first.serverPublic, local, first.keys, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Close()
	if reply, session := s.Handle(ctx, src, staleHello, now.Add(2*time.Second)); reply != nil || session != nil {
		t.Fatal("stale epoch zero accepted after commitment")
	}
}

func TestRenewalRecoversAfterServerStateLoss(t *testing.T) {
	s, first, hello, src, now := fixture(t)
	ctx := context.Background()
	reply, _ := s.Handle(ctx, src, hello, now)
	_, finish, err := first.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	ack, installed := s.Handle(ctx, src, finish, now)
	installed.Installed(true)
	if !first.Accepted(ack) {
		t.Fatal("initial state did not commit")
	}

	local := Keys{WG: src, Disco: [32]byte(first.hello[clientDiscoOffset : clientDiscoOffset+32])}
	renewal, renewedHello, err := NewClientWithState(ctx, first.identity, software.NewKEM, first.serverPublic, local, first.keys, first.State(), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer renewal.Close()
	// A restarted server retains its identity/configuration but no lease-coupled
	// ratchet state. Its zero-root proof authenticates that reset to the client.
	restarted := &Server{Identity: s.Identity, Public: s.Public, Keys: s.Keys, Authorized: s.Authorized}
	reply, _ = restarted.Handle(ctx, src, renewedHello, now.Add(time.Second))
	psk, finish, err := renewal.Complete(ctx, reply)
	if err != nil || psk == [32]byte{} {
		t.Fatalf("state-loss recovery failed: %v", err)
	}
	ack, installed = restarted.Handle(ctx, src, finish, now.Add(time.Second))
	if installed == nil {
		t.Fatal("reset candidate was not installable")
	}
	installed.Installed(true)
	if !renewal.Accepted(ack) || renewal.State().Epoch != 1 {
		t.Fatal("reset state did not retain the client's epoch")
	}
}

func TestExpirePrunesRateTables(t *testing.T) {
	now := time.Now()
	key := [32]byte{1}
	s := &Server{
		limits:     map[[32]byte]bucket{key: {start: now.Add(-2 * time.Second)}},
		peerLimits: map[[32]byte]bucket{key: {start: now.Add(-2 * time.Second)}},
	}
	s.Expire(now)
	if len(s.limits) != 0 || len(s.peerLimits) != 0 {
		t.Fatal("expired rate entries retained")
	}
}

func TestEvictOldest(t *testing.T) {
	now := time.Now()
	old, recent := [32]byte{1}, [32]byte{2}
	table := map[[32]byte]bucket{
		old:    {start: now.Add(-time.Second)},
		recent: {start: now},
	}
	evictOldest(table)
	if _, ok := table[old]; ok || len(table) != 1 {
		t.Fatal("oldest rate entry was not evicted")
	}
}
