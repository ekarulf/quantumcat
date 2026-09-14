package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ekarulf/quantumcat/internal/protocol"
)

func TestPairingAndStorage(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	ctx := context.Background()
	if err := s.Init(ctx, "test", "software"); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx, "test", "software"); err == nil {
		t.Fatal("overwrote existing identity")
	}
	i, _, _, close, err := s.Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	pub, _ := i.PublicKey(ctx)
	p := Peer{Version: 1, Name: "test", PeerID: protocol.ID(pub).String(), PublicKey: pub}
	file := filepath.Join(t.TempDir(), "test.qpeer")
	if err = WriteNew(file, p); err != nil {
		t.Fatal(err)
	}
	if err = s.Add("../escape", file); err == nil {
		t.Fatal("accepted path traversal")
	}
	if err = s.Add("test", file); err != nil {
		t.Fatal(err)
	}
	if err = s.Add("alias", file); err == nil {
		t.Fatal("accepted duplicate identity")
	}
	if err = s.Remove("test"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Peer("test"); err == nil {
		t.Fatal("revoked peer still authorized")
	}
	if _, err = os.Stat(filepath.Join(s.Dir, "peers", "test.qpeer.revoked")); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(s.Dir, "identity.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err = s.Identity(ctx); err == nil {
		t.Fatal("accepted publicly readable identity")
	}
}
