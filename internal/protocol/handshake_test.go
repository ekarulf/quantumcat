package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

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
	if s.global.count != 4 {
		t.Fatalf("source bypassed verification quota: %d", s.global.count)
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
	f.Add(frame(ClientFinish, make([]byte, 64)))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = Parse(b) })
}
