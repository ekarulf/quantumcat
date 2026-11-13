package protocol

import (
	"context"
	"testing"
	"time"
)

func TestRejectedPacketsDoNotSweepTables(t *testing.T) {
	s, _, _, src, now := fixture(t)
	s.pending = map[[hashSize]byte]*pending{{1}: {expires: now.Add(-time.Second)}}
	s.replay = map[[hashSize]byte]time.Time{{1}: now.Add(-time.Second)}
	s.limits = map[[32]byte]bucket{{1}: {start: now.Add(-time.Hour)}}
	for _, kind := range []byte{ClientFinish, ServerAccepted} {
		for n := 0; n < 100; n++ {
			s.Handle(context.Background(), src, frame(kind, make([]byte, hashSize+proofSize)), now)
		}
	}
	if len(s.pending) != 1 || len(s.replay) != 1 || len(s.limits) != 1 {
		t.Fatal("rejected packet swept shared state")
	}
	s.Expire(now)
	if len(s.pending)+len(s.replay)+len(s.limits) != 0 {
		t.Fatal("periodic expiry failed")
	}
}

func TestRotatingSourcesCannotBypassResolutionBudget(t *testing.T) {
	s, _, hello, _, now := fixture(t)
	visited := 0
	s.Authorized = func(yield func(PeerID, []byte) bool) { visited++; yield(PeerID{1}, nil) }
	for n := 0; n < 256; n++ {
		src := [32]byte{byte(n), 1}
		packet := append([]byte(nil), hello...)
		copy(packet[8+32:8+64], src[:])
		s.Handle(context.Background(), src, packet, now)
	}
	if visited != 128 {
		t.Fatalf("resolution scans=%d want 128", visited)
	}
	if len(s.limits) != 128 {
		t.Fatalf("allocated source records=%d", len(s.limits))
	}
}

func TestInvalidFinishDoesNotEnumerateAuthority(t *testing.T) {
	s, c, hello, src, now := fixture(t)
	reply, _ := s.Handle(context.Background(), src, hello, now)
	_, finish, err := c.Complete(context.Background(), reply)
	if err != nil {
		t.Fatal(err)
	}
	finish[len(finish)-1] ^= 1
	s.Authorized = func(func(PeerID, []byte) bool) { t.Fatal("unauthenticated finish enumerated peers") }
	s.Handle(context.Background(), src, finish, now)
}
