// Package trust validates local filesystem objects used as trust inputs.
package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Path requires a non-symlink object of the requested type, owned by root or
// the effective user and not writable by group or others.
func Path(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("%s: expected non-symlink %s", path, map[bool]string{true: "directory", false: "file"}[directory])
	}
	if err := Owner(info); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%s: must not be group/other writable", path)
	}
	return nil
}

// Owner requires ownership by root or the effective user.
func Owner(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		return fmt.Errorf("owner must be root or the current user")
	}
	return nil
}

// Ancestors validates every parent of path. Trusted sticky directories such
// as /tmp are allowed because their entries cannot be replaced by other users.
func Ancestors(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for parent := filepath.Dir(resolved); ; parent = filepath.Dir(parent) {
		info, err := os.Stat(parent)
		if err != nil {
			return err
		}
		if err := Owner(info); err != nil {
			return fmt.Errorf("%s: %w", parent, err)
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%s: ancestor is group/other writable", parent)
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return nil
}
