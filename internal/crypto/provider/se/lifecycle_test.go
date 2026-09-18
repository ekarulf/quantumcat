package se

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHelperEnvironmentNames(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Setenv("QCAT_SE_HELPER", "/legacy/qcat-se")
		t.Setenv("QCAT_ENCLAVE_HELPER", "/new/qcat-se")
		if path, err := helperPath(); err != nil || path != "/new/qcat-se" {
			t.Fatalf("new name: %q %v", path, err)
		}
		t.Setenv("QCAT_ENCLAVE_HELPER", "")
		if path, err := helperPath(); err != nil || path != "/legacy/qcat-se" {
			t.Fatalf("legacy: %q %v", path, err)
		}
		t.Setenv("QCAT_ENCLAVE_HELPER", "relative-path")
		if _, err := helperPath(); err == nil {
			t.Fatal("invalid canonical path fell back to legacy")
		}
	}
	t.Setenv("QCAT_ENCLAVE_HELPER", "")
	t.Setenv("QCAT_SE_HELPER", "")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if path, err := helperPath(); err != nil || path != filepath.Join(filepath.Dir(exe), "qcat-se") {
		t.Fatalf("default: %q %v", path, err)
	}
}

func TestTrustedHelper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "qcat-se")
	if err := os.WriteFile(path, []byte("helper"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := trustedHelper(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0722); err != nil {
		t.Fatal(err)
	}
	if err := trustedHelper(path); err == nil {
		t.Fatal("writable helper trusted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := trustedHelper(path); err == nil {
		t.Fatal("non-executable helper trusted")
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "helper-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := trustedHelper(link); err == nil {
		t.Fatal("symlink helper trusted")
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := trustedHelper(path); err == nil {
		t.Fatal("helper beneath writable directory trusted")
	}
}

func TestHelperChild(t *testing.T) {
	if os.Getenv("QCAT_TEST_STALLED_HELPER") != "1" {
		return
	}
	time.Sleep(time.Minute)
	os.Exit(0)
}

func TestHelperDeathIsObservable(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "external-exit", true: "operation-timeout"}[timeout], func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestHelperChild$")
			cmd.Env = append(os.Environ(), "QCAT_TEST_STALLED_HELPER=1")
			h, err := start(cmd)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			if timeout {
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()
				if _, err := h.call(ctx, 3, nil); err == nil {
					t.Fatal("stalled helper succeeded")
				}
			} else if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-h.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("helper death not reported")
			}
		})
	}
}
