package tailcat

import (
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestOldestSessionForIdentity(t *testing.T) {
	identity, other := [32]byte{1}, [32]byte{2}
	oldest := key.NewNode().Public()
	newer := key.NewNode().Public()
	unrelated := key.NewNode().Public()
	now := time.Now()
	owners := map[key.NodePublic][32]byte{oldest: identity, newer: identity, unrelated: other}
	installed := map[key.NodePublic]time.Time{
		oldest:    now.Add(-time.Minute),
		newer:     now,
		unrelated: now.Add(-time.Hour),
	}
	got, count := oldestSessionForIdentity(owners, installed, identity)
	if count != 2 || got != oldest {
		t.Fatalf("got oldest %v and count %d", got, count)
	}
}
