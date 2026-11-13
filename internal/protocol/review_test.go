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
	authorized := s.Authorized
	s.Authorized = func(yield func(PeerID, []byte) bool) {
		if !yield(ID(pub), pub) {
			return
		}
		authorized(yield)
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

func TestCompletedHandshakesDoNotConsumePendingQuota(t *testing.T) {
	s, client, _, _, now := fixture(t)
	ctx := context.Background()
	for n := 0; n < 9; n++ {
		at := now.Add(time.Duration(n) * 500 * time.Millisecond)
		src := [32]byte{byte(n + 1)}
		c, hello, err := NewClient(ctx, client.identity, software.NewKEM, client.serverPublic, Keys{WG: src, Disco: [32]byte{1}}, client.keys, at)
		if err != nil {
			t.Fatal(err)
		}
		reply, _ := s.Handle(ctx, src, hello, at)
		if len(reply) == 0 {
			t.Fatalf("hello %d rejected", n+1)
		}
		_, finish, err := c.Complete(ctx, reply)
		if err != nil {
			t.Fatal(err)
		}
		ack, session := s.Handle(ctx, src, finish, at)
		if session == nil || !c.Accepted(ack) {
			t.Fatal("finish rejected")
		}
		session.Installed(true)
		ack, duplicate := s.Handle(ctx, src, finish, at)
		if duplicate != nil || !c.Accepted(ack) {
			t.Fatal("duplicate reinstalled or lost ack")
		}
		c.Close()
	}
	if s.unfinished() != 0 {
		t.Fatal("completed work charged to pending quota")
	}
}

func TestCompletedRetryOverflowPreservesUnfinished(t *testing.T) {
	s, c, hello, src, now := fixture(t)
	reply, _ := s.Handle(context.Background(), src, hello, now)
	_, finish, err := c.Complete(context.Background(), reply)
	if err != nil {
		t.Fatal(err)
	}
	_, session := s.Handle(context.Background(), src, finish, now)
	if session == nil {
		t.Fatal("no installation")
	}
	for n := 0; n < 2048; n++ {
		var hash [hashSize]byte
		binary.BigEndian.PutUint64(hash[:], uint64(n+1))
		s.pending[hash] = &pending{hash: hash, accepted: true, expires: now.Add(-time.Second)}
	}
	unfinishedHash := [hashSize]byte{99, 99}
	s.pending[unfinishedHash] = &pending{hash: unfinishedHash, expires: now.Add(-time.Hour)}
	session.Installed(true)
	if len(s.pending) != 2049 || s.pending[unfinishedHash] == nil {
		t.Fatal("retry overflow evicted unfinished work or exceeded bound")
	}
	if ack, again := s.Handle(context.Background(), src, finish, now); again != nil || !c.Accepted(ack) {
		t.Fatal("new retry record lost")
	}
}
