package protocol

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/ekarulf/quantumcat/internal/crypto/provider/software"
)

func TestReplayCapacityCoversGlobalBudget(t *testing.T) {
	s, _, hello, source, now := fixture(t)
	s.pending = make(map[[hashSize]byte]*pending)
	s.replay = make(map[[hashSize]byte]time.Time)
	for n := 0; n < 4096; n++ {
		var key [hashSize]byte
		binary.BigEndian.PutUint64(key[:8], uint64(n))
		s.replay[key] = now.Add(5 * time.Minute)
	}
	if reply, _ := s.Handle(context.Background(), source, hello, now); len(reply) == 0 {
		t.Fatal("old replay-table limit still blocks legitimate handshake")
	}
}

func TestSupersededFinishCannotReinstallPSK(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "in-flight", true: "committed"}[installed], func(t *testing.T) {
			s, first, hello, src, now := fixture(t)
			ctx := context.Background()
			reply, _ := s.Handle(ctx, src, hello, now)
			_, oldFinish, err := first.Complete(ctx, reply)
			if err != nil {
				t.Fatal(err)
			}
			next, hello, err := NewClient(ctx, first.identity, software.NewKEM, first.serverPublic, Keys{WG: src, Disco: [32]byte{1}}, first.keys, now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			reply, _ = s.Handle(ctx, src, hello, now.Add(time.Second))
			psk, finish, err := next.Complete(ctx, reply)
			if err != nil {
				t.Fatal(err)
			}
			_, session := s.Handle(ctx, src, finish, now.Add(2*time.Second))
			if session == nil || session.PSK != psk {
				t.Fatal("new session not installed")
			}
			if installed {
				session.Installed(true)
			}
			if ack, stale := s.Handle(ctx, src, oldFinish, now.Add(3*time.Second)); ack != nil || stale != nil {
				t.Fatal("stale finish accepted")
			}
			if !installed {
				session.Installed(true)
			}
			if ack, duplicate := s.Handle(ctx, src, finish, now.Add(4*time.Second)); duplicate != nil || !next.Accepted(ack) {
				t.Fatal("current finish retry lost its acknowledgement")
			}
		})
	}
}

func TestPendingQuotaSharedByIdentityAcrossSources(t *testing.T) {
	s, client, _, _, now := fixture(t)
	ctx := context.Background()
	for n := 0; n < 9; n++ {
		source := [32]byte{byte(n + 1)}
		c, hello, err := NewClient(ctx, client.identity, software.NewKEM, client.serverPublic, Keys{WG: source, Disco: [32]byte{1}}, client.keys, now.Add(time.Duration(n)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		reply, _ := s.Handle(ctx, source, hello, now.Add(time.Duration(n)*time.Second))
		c.Close()
		if (len(reply) > 0) != (n < 8) {
			t.Fatalf("identity quota at request %d", n)
		}
	}
	if len(s.pending) != 8 {
		t.Fatalf("pending=%d", len(s.pending))
	}
	// Another identity still gets service.
	other, err := software.Generate()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	pub, _ := other.PublicKey(ctx)
	lookup := s.Lookup
	s.Lookup = func(id PeerID) []byte {
		if id == ID(pub) {
			return pub
		}
		return lookup(id)
	}
	c, hello, err := NewClient(ctx, other, software.NewKEM, client.serverPublic, Keys{WG: [32]byte{99}, Disco: [32]byte{1}}, client.keys, now.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if reply, _ := s.Handle(ctx, [32]byte{99}, hello, now.Add(10*time.Second)); len(reply) == 0 {
		t.Fatal("one identity blocked another")
	}
}

func TestTokenBucketDoesNotResetAtWindowBoundary(t *testing.T) {
	now := time.Unix(100, 0)
	b, _ := allow(bucket{}, now, 4)
	for range 4 {
		b, _ = allow(b, now.Add(990*time.Millisecond), 4)
	}
	if _, ok := allow(b, now.Add(time.Second), 4); ok {
		t.Fatal("fixed-window double burst")
	}
	if _, ok := allow(b, now.Add(1250*time.Millisecond), 4); !ok {
		t.Fatal("tokens did not refill")
	}
	if _, ok := allow(b, now.Add(-time.Second), 4); ok {
		t.Fatal("backward time refilled bucket")
	}
}
