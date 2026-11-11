package se

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ekarulf/quantumcat/internal/trust"
)

// Pin discovery to the startup installation. A running qcat must not switch
// helper versions when Homebrew retargets a bin/opt alias during an upgrade.
var qcatExecutable, qcatExecutableErr = resolveExecutable()

func resolveExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	// Homebrew's bin and opt links must select the helper from the same keg,
	// rather than from the global prefix or another installed version.
	return filepath.EvalSymlinks(exe)
}

func helperPath() (string, error) {
	unprivileged, err := helperProcessPolicy(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid())
	if err != nil {
		return "", err
	}
	if qcatExecutableErr != nil {
		return "", fmt.Errorf("resolve qcat executable: %w", qcatExecutableErr)
	}
	return findHelper(qcatExecutable, helperOverride(unprivileged, os.Getenv), unprivileged)
}

func helperProcessPolicy(uid, euid, gid, egid int) (unprivileged bool, err error) {
	// Merely ignoring environment overrides is not enough for setgid: a
	// user-owned helper would still inherit the process's elevated group.
	if uid != euid || gid != egid {
		return false, errors.New("Secure Enclave helper is unsupported in set-ID processes; run qcat without setuid/setgid")
	}
	return euid != 0, nil
}

func helperOverride(unprivileged bool, getenv func(string) string) string {
	// Environment-controlled executables must never cross a privilege boundary.
	if !unprivileged {
		return ""
	}
	if path := getenv("QCAT_ENCLAVE_HELPER"); path != "" {
		return path
	}
	return getenv("QCAT_SE_HELPER") // Compatibility with existing LaunchAgents.
}

func helperCandidates(exe string) []string {
	dir := filepath.Dir(exe)
	var paths []string
	if filepath.Base(dir) == "bin" || filepath.Base(dir) == "sbin" {
		prefix := filepath.Dir(dir)
		paths = append(paths,
			filepath.Join(prefix, "libexec", "qcat", "qcat-se"),
			filepath.Join(prefix, "libexec", "qcat-se"),
			filepath.Join(prefix, "sbin", "qcat-se"))
	}
	return append(paths, filepath.Join(dir, "qcat-se"))
}

func findHelper(exe, override string, unprivileged bool) (string, error) {
	paths := helperCandidates(exe)
	if override != "" {
		if !filepath.IsAbs(override) {
			return "", errors.New("QCAT_ENCLAVE_HELPER must be an absolute path")
		}
		paths = []string{override}
	}
	for _, path := range paths {
		// Lstat distinguishes an absent candidate from an invalid/dangling link.
		// Never silently fall back after finding an unsafe installation.
		if err := helperCandidateExists(path); errors.Is(err, os.ErrNotExist) && override == "" {
			continue
		} else if err != nil {
			return "", fmt.Errorf("Secure Enclave helper %s: %w", path, err)
		}
		resolved, err := trustedHelper(path, exe, unprivileged)
		if err != nil {
			return "", fmt.Errorf("untrusted Secure Enclave helper: %w", err)
		}
		return resolved, nil
	}
	return "", fmt.Errorf("Secure Enclave helper not found (run make helper or install qcat-se); searched %s", strings.Join(paths, ", "))
}

// A missing ordinary directory is an absent layout. A dangling ancestor link is
// a broken installation and must not silently select a different helper.
func helperCandidateExists(path string) error {
	_, err := os.Lstat(path)
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, parentErr := os.Lstat(parent)
		if parentErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				if _, linkErr := filepath.EvalSymlinks(parent); linkErr != nil {
					return fmt.Errorf("invalid helper directory %s: %v", parent, linkErr)
				}
			}
			return err
		}
		if !errors.Is(parentErr, os.ErrNotExist) {
			return parentErr
		}
		if parent == filepath.Dir(parent) {
			return err
		}
	}
}

// trustedHelper returns the exact canonical path to execute. Resolving and then
// executing the original alias would allow the alias to be retargeted between
// the trust check and exec. Configuration and identity files retain their
// separate, stricter no-symlink policy in internal/trust.
func trustedHelper(path, exe string, unprivileged bool) (string, error) {
	resolved, err := resolveHelperLinks(path, exe, unprivileged)
	if err != nil {
		return "", err
	}
	// Check the canonical chain root-to-leaf without following any new links.
	// In particular, don't use Ancestors, which independently resolves aliases.
	var parents []string
	for parent := filepath.Dir(resolved); ; parent = filepath.Dir(parent) {
		parents = append(parents, parent)
		if parent == filepath.Dir(parent) {
			break
		}
	}
	for i := len(parents) - 1; i >= 0; i-- {
		parent := parents[i]
		info, err := os.Lstat(parent)
		if err != nil {
			return "", err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%s: expected non-symlink directory", parent)
		}
		if err := trust.Owner(info); err != nil {
			return "", fmt.Errorf("%s: %w", parent, err)
		}
		// Homebrew may make shared installation ancestors admin-group writable.
		// An unprivileged qcat already trusts those same directories for its own
		// code. Permit only that existing trust, never helper-only directories,
		// world-writable directories, or a root/set-ID invocation.
		shared := unprivileged && pathWithin(exe, parent)
		if err := helperDirectoryMode(info.Mode(), shared); err != nil {
			return "", fmt.Errorf("%s: %w", parent, err)
		}
	}
	if err := trust.Path(resolved, false); err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0111 == 0 {
		return "", errors.New("helper is not executable")
	}
	return resolved, nil
}

// Validate the entire alias chain, not just the final target: an untrusted link
// must not be able to select an unrelated, otherwise trusted executable.
func resolveHelperLinks(path, exe string, unprivileged bool) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("helper must be an absolute path")
	}
	resolved := string(filepath.Separator)
	parts := strings.Split(path, string(filepath.Separator))
	links := 0
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, part)
		info, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if err := trust.Owner(info); err != nil {
			return "", fmt.Errorf("%s: %w", next, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 255 {
				return "", errors.New("too many helper symlinks")
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(target) {
				resolved = string(filepath.Separator)
			}
			parts = append(strings.Split(target, string(filepath.Separator)), parts...)
			continue
		}
		if info.IsDir() {
			if err := helperDirectoryMode(info.Mode(), unprivileged && pathWithin(exe, next)); err != nil {
				return "", fmt.Errorf("%s: %w", next, err)
			}
		} else if len(parts) > 0 {
			return "", fmt.Errorf("%s: expected directory", next)
		}
		resolved = next
	}
	return resolved, nil
}

func pathWithin(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func helperDirectoryMode(mode os.FileMode, shared bool) error {
	if mode&os.ModeSticky != 0 {
		return nil // Trusted sticky directories such as /tmp protect their entries.
	}
	if mode.Perm()&0002 != 0 || (mode.Perm()&0020 != 0 && !shared) {
		return errors.New("ancestor is group/other writable")
	}
	return nil
}
