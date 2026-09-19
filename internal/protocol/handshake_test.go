package protocol

import (
	"bytes"
	"context"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
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
	s := &Server{Identity: si, Public: sp, Keys: remote, Lookup: func(id PeerID) []byte {
		if id == ID(cp) {
			return cp
		}
		return nil
	}}
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

func TestFailedInstallationCannotBeAcknowledgedOnRetry(t *testing.T) {
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
	if ack, next := s.Handle(ctx, src, finish, now); ack != nil || next != nil {
		t.Fatal("acknowledged rejected installation")
	}
	if len(s.pending) != 0 {
		t.Fatal("retained rejected session secrets")
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
				s.Lookup = func(PeerID) []byte { return nil }
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
				s.Lookup = func(PeerID) []byte { return nil }
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
	if transcriptSize != 3483 || transcriptSize <= hashSize {
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
	psk, confirmation, err := derive(ss, hash)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(psk[:]), "4382598d92933ba95a56715c284157d77f3f9b99dff5a654c74455670421d02d"; got != want {
		t.Fatalf("PSK = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(confirmation[:]), "376e3da389d23edb393e42bde1abedebae3b87dd86439fb85ebbdb9c3c8abd02"; got != want {
		t.Fatalf("confirmation = %s, want %s", got, want)
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
