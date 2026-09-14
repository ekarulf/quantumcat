package config

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAuthorizationStoreIntegrity(t *testing.T) {
	for _, target := range []string{".", "peers", "peers/peer.qpeer"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			s := Store{Dir: dir}
			if err := s.Init(context.Background(), "test", "software"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, "peers"), 0750); err != nil {
				t.Fatal(err)
			}
			// A malformed descriptor should already fail closed; permissions must be
			// rejected before parsing even when the contents might otherwise be valid.
			file := filepath.Join(dir, "peers/peer.qpeer")
			if err := os.WriteFile(file, []byte("{}"), 0640); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, target)
			mode := os.FileMode(0770)
			if target == "peers/peer.qpeer" {
				mode = 0660
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Peers(); err == nil {
				t.Fatal("accepted writable authorization store")
			}
			if err := trustedPath(path, target != "peers/peer.qpeer"); err == nil {
				t.Fatal("writable path trusted")
			}
		})
	}
}

func TestReadOnlyGroupAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peer.qpeer")
	if err := os.WriteFile(path, []byte("{}"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := trustedPath(path, false); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := trustedPath(link, false); err == nil {
		t.Fatal("symlink trusted")
	}
}

func TestUnsafeAncestorAndIdentitySymlink(t *testing.T) {
	parent := t.TempDir()
	s := Store{Dir: filepath.Join(parent, "config")}
	if err := s.Init(context.Background(), "test", "software"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := s.Identity(context.Background()); err == nil {
		t.Fatal("writable ancestor accepted")
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, "identity.json")
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".original", path); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := s.Identity(context.Background()); err == nil {
		t.Fatal("identity symlink accepted")
	}
}

type ownerInfo struct {
	os.FileInfo
	uid uint32
}

func (i ownerInfo) Sys() any { return &syscall.Stat_t{Uid: i.uid} }
func TestTrustedOwnership(t *testing.T) {
	for _, uid := range []uint32{0, uint32(os.Geteuid())} {
		if err := trustedOwner(ownerInfo{uid: uid}); err != nil {
			t.Fatal(err)
		}
	}
	if err := trustedOwner(ownerInfo{uid: uint32(os.Geteuid() + 10000)}); err == nil {
		t.Fatal("foreign owner trusted")
	}
}
