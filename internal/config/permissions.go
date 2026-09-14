package config

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Public peer keys are not confidential, but their integrity is authorization.
// Root-owned 0750 directories and 0640 files support a root-managed service.
func trustedPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("%s: expected non-symlink %s", path, map[bool]string{true: "directory", false: "file"}[directory])
	}
	if err := trustedOwner(info); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%s: must not be group/other writable", path)
	}
	return nil
}

func trustedOwner(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		return fmt.Errorf("owner must be root or the current user")
	}
	return nil
}

func (s Store) checkStore() error {
	path, err := filepath.Abs(s.Dir)
	if err != nil {
		return err
	}
	if err := trustedPath(path, true); err != nil {
		return err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	// Check ancestors too: a safe-looking peers directory is not enough if a
	// different account can replace the whole config directory. Permit trusted
	// sticky temporary parents (e.g. /tmp) used by private test/config roots.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Stat(parent)
		if err != nil {
			return err
		}
		if err := trustedOwner(info); err != nil {
			return fmt.Errorf("%s: %w", parent, err)
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%s: config ancestor is group/other writable", parent)
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return nil
}

func (s Store) checkPeers() error {
	if err := s.checkStore(); err != nil {
		return err
	}
	return trustedPath(filepath.Join(s.Dir, "peers"), true)
}
