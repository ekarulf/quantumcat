package se

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testExecutable(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("helper"), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func testSymlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func canonical(t *testing.T, path string) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHelperEnvironmentNames(t *testing.T) {
	env := map[string]string{"QCAT_SE_HELPER": "/legacy/qcat-se", "QCAT_ENCLAVE_HELPER": "/new/qcat-se"}
	getenv := func(key string) string { return env[key] }
	if got := helperOverride(true, getenv); got != "/new/qcat-se" {
		t.Fatalf("new name: %q", got)
	}
	delete(env, "QCAT_ENCLAVE_HELPER")
	if got := helperOverride(true, getenv); got != "/legacy/qcat-se" {
		t.Fatalf("legacy: %q", got)
	}
	env["QCAT_ENCLAVE_HELPER"] = "relative-path"
	exe := testExecutable(t, filepath.Join(t.TempDir(), "qcat"))
	if _, err := findHelper(exe, helperOverride(true, getenv), true); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("invalid canonical path fell back to legacy: %v", err)
	}
	for _, ids := range [][4]int{{1000, 0, 1000, 1000}, {1000, 1001, 1000, 1000}, {1000, 1000, 1000, 1001}, {0, 0, 0, 1000}} {
		if allowed, err := helperProcessPolicy(ids[0], ids[1], ids[2], ids[3]); err == nil || allowed || helperOverride(allowed, getenv) != "" {
			t.Fatalf("set-ID process accepted: %v", ids)
		}
	}
	if allowed, err := helperProcessPolicy(0, 0, 0, 0); err != nil || allowed || helperOverride(allowed, getenv) != "" {
		t.Fatalf("ordinary root invocation: allowed %v, err %v", allowed, err)
	}
	if allowed, err := helperProcessPolicy(1000, 1000, 1000, 1000); !allowed || err != nil {
		t.Fatal("ordinary user treated as privileged")
	}
}

func TestHelperExplicitLocationAndNoPathSearch(t *testing.T) {
	prefix := t.TempDir()
	exe := canonical(t, testExecutable(t, filepath.Join(prefix, "bin", "qcat")))
	custom := testExecutable(t, filepath.Join(t.TempDir(), "private", "qcat-se"))
	t.Setenv("PATH", filepath.Dir(custom))
	if _, err := findHelper(exe, "", true); err == nil {
		t.Fatal("helper discovered on PATH")
	}
	testExecutable(t, filepath.Join(prefix, "libexec", "qcat-se"))
	if got, err := findHelper(exe, custom, true); err != nil || got != canonical(t, custom) {
		t.Fatalf("explicit location: got %q, %v", got, err)
	}
	if _, err := findHelper(exe, custom+"-missing", true); err == nil {
		t.Fatal("missing explicit location fell back to installed helper")
	}
}

func TestHelperInstallLayouts(t *testing.T) {
	for _, layout := range []string{"libexec/qcat/qcat-se", "libexec/qcat-se", "sbin/qcat-se", "bin/qcat-se"} {
		t.Run(layout, func(t *testing.T) {
			prefix := filepath.Join(t.TempDir(), "Cellar", "quantumcat", "1.2.3")
			exe := testExecutable(t, filepath.Join(prefix, "bin", "qcat"))
			helper := testExecutable(t, filepath.Join(prefix, filepath.FromSlash(layout)))
			if got, err := findHelper(canonical(t, exe), "", true); err != nil || got != canonical(t, helper) {
				t.Fatalf("got %q, %v; want %q", got, err, helper)
			}
		})
	}
	t.Run("development", func(t *testing.T) {
		dir := t.TempDir()
		exe := testExecutable(t, filepath.Join(dir, "qcat"))
		helper := testExecutable(t, filepath.Join(dir, "qcat-se"))
		if got, err := findHelper(canonical(t, exe), "", true); err != nil || got != canonical(t, helper) {
			t.Fatalf("got %q, %v", got, err)
		}
		if paths := helperCandidates(exe); len(paths) != 1 {
			t.Fatalf("development build searched unrelated prefix: %v", paths)
		}
	})
}

func TestHomebrewAliasesStayInKeg(t *testing.T) {
	brew := t.TempDir()
	keg := filepath.Join(brew, "Cellar", "quantumcat", "1.2.3")
	exe := testExecutable(t, filepath.Join(keg, "bin", "qcat"))
	helper := testExecutable(t, filepath.Join(keg, "libexec", "qcat-se"))
	// A different global helper must never win over the active keg's helper.
	testExecutable(t, filepath.Join(brew, "bin", "qcat-se"))
	binLink := filepath.Join(brew, "bin", "qcat")
	testSymlink(t, "../Cellar/quantumcat/1.2.3/bin/qcat", binLink)
	optLink := filepath.Join(brew, "opt", "quantumcat")
	testSymlink(t, "../Cellar/quantumcat/1.2.3", optLink)
	for _, launch := range []string{exe, binLink, filepath.Join(optLink, "bin", "qcat")} {
		if got, err := findHelper(canonical(t, launch), "", true); err != nil || got != canonical(t, helper) {
			t.Fatalf("launch %q: got %q, %v", launch, got, err)
		}
	}
}

func TestHelperDiscoveryPinnedAtStartup(t *testing.T) {
	if prefix := os.Getenv("QCAT_TEST_DISCOVERY_ROOT"); prefix != "" {
		launch := filepath.Join(prefix, "bin", "qcat")
		if err := os.Remove(launch); err != nil {
			t.Fatal(err)
		}
		testSymlink(t, "../Cellar/quantumcat/2/bin/qcat", launch)
		want := canonical(t, filepath.Join(prefix, "Cellar", "quantumcat", "1", "libexec", "qcat-se"))
		if got, err := helperPath(); err != nil || got != want {
			t.Fatalf("upgrade changed running process's helper: got %q, %v; want %q", got, err, want)
		}
		return
	}
	prefix := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	old := testExecutable(t, filepath.Join(prefix, "Cellar", "quantumcat", "1", "bin", "qcat"))
	if err := os.WriteFile(old, binary, 0755); err != nil {
		t.Fatal(err)
	}
	testExecutable(t, filepath.Join(prefix, "Cellar", "quantumcat", "1", "libexec", "qcat-se"))
	testExecutable(t, filepath.Join(prefix, "Cellar", "quantumcat", "2", "bin", "qcat"))
	testExecutable(t, filepath.Join(prefix, "Cellar", "quantumcat", "2", "libexec", "qcat-se"))
	launch := filepath.Join(prefix, "bin", "qcat")
	testSymlink(t, "../Cellar/quantumcat/1/bin/qcat", launch)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, launch, "-test.run=^TestHelperDiscoveryPinnedAtStartup$")
	cmd.Env = append(os.Environ(), "QCAT_TEST_DISCOVERY_ROOT="+prefix, "QCAT_ENCLAVE_HELPER=", "QCAT_SE_HELPER=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subprocess: %v\n%s", err, out)
	}
}

func TestHelperSelectionFailsClosed(t *testing.T) {
	for _, bad := range []string{"non-executable", "writable", "directory", "dangling", "dangling-ancestor", "loop"} {
		t.Run(bad, func(t *testing.T) {
			prefix := t.TempDir()
			exe := testExecutable(t, filepath.Join(prefix, "bin", "qcat"))
			testExecutable(t, filepath.Join(prefix, "bin", "qcat-se"))
			path := filepath.Join(prefix, "libexec", "qcat-se")
			switch bad {
			case "non-executable", "writable":
				testExecutable(t, path)
				mode := os.FileMode(0644)
				if bad == "writable" {
					mode = 0775
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "dangling":
				testSymlink(t, "missing", path)
			case "dangling-ancestor":
				testSymlink(t, "missing", filepath.Dir(path))
			case "loop":
				testSymlink(t, "qcat-se", path)
			}
			if got, err := findHelper(canonical(t, exe), "", true); err == nil {
				t.Fatalf("unsafe preferred helper %s fell back to %q", bad, got)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		exe := testExecutable(t, filepath.Join(t.TempDir(), "qcat"))
		if _, err := findHelper(canonical(t, exe), "", true); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("missing helper: %v", err)
		}
	})
}

func TestHelperRejectsUntrustedAliasSelection(t *testing.T) {
	for _, mode := range []os.FileMode{0777, 0775} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			exe := testExecutable(t, filepath.Join(dir, "bin", "qcat"))
			trusted := testExecutable(t, filepath.Join(dir, "safe", "qcat-se"))
			alias := filepath.Join(dir, "untrusted", "qcat-se")
			testSymlink(t, trusted, alias)
			testSymlink(t, "../untrusted", filepath.Join(dir, "libexec", "qcat"))
			if err := os.Chmod(filepath.Dir(alias), mode); err != nil {
				t.Fatal(err)
			}
			for _, unprivileged := range []bool{false, true} {
				if _, err := findHelper(canonical(t, exe), "", unprivileged); err == nil {
					t.Fatal("untrusted alias selected an otherwise trusted executable")
				}
			}
		})
	}
}

func TestHelperRelativeLinksAndDotDot(t *testing.T) {
	dir := t.TempDir()
	exe := testExecutable(t, filepath.Join(dir, "bin", "qcat"))
	helper := testExecutable(t, filepath.Join(dir, "private", "qcat-se"))
	if err := os.Mkdir(filepath.Join(dir, "private", "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "libexec", "qcat-se")
	testSymlink(t, "../private/subdir/../qcat-se", link)
	got, err := trustedHelper(link, canonical(t, exe), true)
	if err != nil || got != canonical(t, helper) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestHelperMultiHopDirectoryAliases(t *testing.T) {
	dir := t.TempDir()
	exe := testExecutable(t, filepath.Join(dir, "bin", "qcat"))
	helper := testExecutable(t, filepath.Join(dir, "private", "var", "qcat", "qcat-se"))
	// Model macOS /var -> /private/var, then another relative helper link.
	testSymlink(t, "private/var", filepath.Join(dir, "var"))
	testSymlink(t, "../var/qcat", filepath.Join(dir, "libexec", "qcat"))
	got, err := findHelper(canonical(t, exe), "", true)
	if err != nil || got != canonical(t, helper) {
		t.Fatalf("multi-hop directory aliases: got %q, %v", got, err)
	}
	if err := os.Chmod(filepath.Join(dir, "private", "var"), 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := findHelper(canonical(t, exe), "", true); err == nil {
		t.Fatal("writable intermediate directory trusted through aliases")
	}
}

func TestHelperSymlinkExecutesCanonicalTarget(t *testing.T) {
	dir := t.TempDir()
	exe := testExecutable(t, filepath.Join(dir, "bin", "qcat"))
	helper := testExecutable(t, filepath.Join(dir, "private", "qcat-se"))
	link := filepath.Join(dir, "libexec", "qcat-se")
	testSymlink(t, "../private/qcat-se", link)
	got, err := findHelper(canonical(t, exe), "", true)
	if err != nil || got != canonical(t, helper) {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	testSymlink(t, "missing", link)
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("retargeting original alias changed execution path: %v", err)
	}
	if err := os.Chmod(filepath.Dir(helper), 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedHelper(helper, canonical(t, exe), true); err == nil {
		t.Fatal("writable target ancestor trusted")
	}
}

func TestHelperDirectoryTrust(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   os.FileMode
		shared bool
		ok     bool
	}{
		{"ordinary", 0755, false, true},
		{"homebrew-shared", 0775, true, true},
		{"privileged", 0775, false, false},
		{"helper-only", 0775, false, false},
		{"world-writable", 0777, true, false},
		{"trusted-sticky", 0777 | os.ModeSticky, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := helperDirectoryMode(tc.mode, tc.shared); (err == nil) != tc.ok {
				t.Fatalf("mode %v shared %v: %v", tc.mode, tc.shared, err)
			}
		})
	}
	prefix := t.TempDir()
	exe := testExecutable(t, filepath.Join(prefix, "bin", "qcat"))
	helper := testExecutable(t, filepath.Join(prefix, "libexec", "qcat-se"))
	if err := os.Chmod(prefix, 0775); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedHelper(helper, canonical(t, exe), true); err != nil {
		t.Fatalf("shared Homebrew prefix: %v", err)
	}
	if _, err := trustedHelper(helper, canonical(t, exe), false); err == nil {
		t.Fatal("privileged process trusted group-writable prefix")
	}
	if err := os.Chmod(filepath.Dir(helper), 0775); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedHelper(helper, canonical(t, exe), true); err == nil {
		t.Fatal("helper-only group-writable directory trusted")
	}
	if pathWithin("/prefix-other/bin/qcat", "/prefix") {
		t.Fatal("common string prefix treated as shared ancestor")
	}
}

func TestRootRejectsUserOwnedHelper(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create foreign-owned fixtures")
	}
	for _, target := range []string{"helper", "ancestor", "sticky-ancestor", "symlink"} {
		t.Run(target, func(t *testing.T) {
			prefix := t.TempDir()
			exe := testExecutable(t, filepath.Join(prefix, "bin", "qcat"))
			helper := testExecutable(t, filepath.Join(prefix, "libexec", "qcat-se"))
			path := helper
			if target == "symlink" {
				path = filepath.Join(prefix, "qcat-se-link")
				testSymlink(t, helper, path)
				helper = path
			} else if target != "helper" {
				path = filepath.Dir(helper)
			}
			if target == "sticky-ancestor" {
				if err := os.Chmod(path, 0777|os.ModeSticky); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Lchown(path, 10001, -1); err != nil {
				t.Fatal(err)
			}
			if _, err := trustedHelper(helper, canonical(t, exe), false); err == nil {
				t.Fatal("root trusted user-owned helper installation")
			}
		})
	}
}
