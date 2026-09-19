package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ekarulf/quantumcat/internal/config"
	"github.com/ekarulf/quantumcat/internal/protocol"
)

func TestPublishedTCPFilter(t *testing.T) {
	ports := publishedTCPPorts(map[uint16]string{22: "127.0.0.1:22", 1080: "127.0.0.1:1080"})
	want := map[uint16]bool{1: true, 22: true, 1080: true}
	for _, p := range ports {
		if p.First != p.Last || !want[p.First] {
			t.Fatalf("unexpected range: %+v", p)
		}
		delete(want, p.First)
	}
	if len(want) != 0 || len(ports) != 3 {
		t.Fatal("missing published port")
	}
}

func TestReloadFailsClosedAndReportsRecovery(t *testing.T) {
	s := config.Store{Dir: t.TempDir()}
	ctx := context.Background()
	if err := s.Init(ctx, "server", "software"); err != nil {
		t.Fatal(err)
	}
	i, _, _, close, err := s.Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	pub, _ := i.PublicKey(ctx)
	path := filepath.Join(s.Dir, "peers", "valid.qpeer")
	if err := config.WriteNew(path, config.Peer{Version: config.PeerVersion, Name: "valid", PeerID: protocol.ID(pub).String(), PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	state := authorizationReload{}
	current := reloadAuthorizations(s, &log, &state, nil)
	if len(current) != 1 {
		t.Fatal("valid peer missing")
	}
	bad := filepath.Join(s.Dir, "peers", "bad.qpeer")
	if err := os.WriteFile(bad, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if len(reloadAuthorizations(s, &log, &state, current)) != 1 {
		t.Fatal("transient invalid config revoked access")
	}
	if !strings.Contains(log.String(), "bad.qpeer") {
		t.Fatal("missing offending filename")
	}
	n := log.Len()
	reloadAuthorizations(s, &log, &state, current)
	if log.Len() != n {
		t.Fatal("repeated error flooded logs")
	}
	if len(reloadAuthorizations(s, &log, &state, current)) != 0 {
		t.Fatal("persistent invalid config retained access")
	}
	if err := os.Remove(bad); err != nil {
		t.Fatal(err)
	}
	if len(reloadAuthorizations(s, &log, &state, nil)) != 1 || state.failures != 0 {
		t.Fatal("valid configuration did not recover")
	}
	if !strings.Contains(log.String(), "valid again") {
		t.Fatal("recovery was silent")
	}
}
