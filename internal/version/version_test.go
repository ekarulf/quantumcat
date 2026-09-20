package version

import (
	"strings"
	"testing"
	"time"
)

func TestShortNamesReleasesByTagAndDevelopmentBuildsByCommit(t *testing.T) {
	commit := "012770f2490680ac1ffc9f1e214688ae03b31137"
	for name, c := range map[string]struct {
		build Build
		want  string
	}{
		// A tag identifies a release on its own, so repeating the commit would
		// only add noise. "devel" identifies nothing, so it needs the commit.
		"release":            {Build{Version: "v1.2.3", Revision: commit}, "v1.2.3"},
		"release modified":   {Build{Version: "v1.2.3", Revision: commit, Dirty: true}, "v1.2.3 (modified)"},
		"development":        {Build{Version: devel, Revision: commit}, "devel 012770f24906"},
		"development dirty":  {Build{Version: devel, Revision: commit, Dirty: true}, "devel 012770f24906 (modified)"},
		"development no vcs": {Build{Version: devel}, "devel"},
		"short revision":     {Build{Version: devel, Revision: "012770f"}, "devel 012770f"},
		"module proxy":       {Build{Version: "v1.2.3"}, "v1.2.3"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := c.build.Short(); got != c.want {
				t.Fatalf("Short() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestStringOmitsUnknownMetadata(t *testing.T) {
	full := Build{
		Version:  "v1.2.3",
		Revision: "012770f2490680ac1ffc9f1e214688ae03b31137",
		Time:     time.Date(2026, 9, 20, 4, 43, 47, 0, time.UTC),
		Go:       "go1.27.1",
		Platform: "darwin/arm64",
	}
	want := "qcat v1.2.3\n" +
		"commit    012770f2490680ac1ffc9f1e214688ae03b31137\n" +
		"committed 2026-09-20T04:43:47Z\n" +
		"go        go1.27.1 darwin/arm64\n"
	if got := full.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	// Module-proxy installs have no commit or commit time. Printing empty
	// fields would suggest the information was lost rather than never recorded.
	bare := Build{Version: "v1.2.3", Go: "go1.27.1", Platform: "linux/amd64"}
	if got := bare.String(); got != "qcat v1.2.3\ngo        go1.27.1 linux/amd64\n" {
		t.Fatalf("String() without VCS metadata = %q", got)
	}
}

func TestCurrentPrefersTheInjectedVersion(t *testing.T) {
	t.Cleanup(func() { Version = "" })
	Version = "v9.9.9"
	if got := Current().Version; got != "v9.9.9" {
		t.Fatalf("Current().Version = %q, want the injected version", got)
	}
}

func TestCurrentAlwaysDescribesTheBinary(t *testing.T) {
	// This runs against whatever the toolchain actually stamped, so it asserts
	// only the invariants: every field that does not depend on VCS metadata is
	// populated, and the version is never blank.
	b := Current()
	if b.Version == "" {
		t.Error("Current() reported no version")
	}
	if !strings.HasPrefix(b.Go, "go") {
		t.Errorf("Current().Go = %q, want a toolchain version", b.Go)
	}
	if !strings.Contains(b.Platform, "/") {
		t.Errorf("Current().Platform = %q, want GOOS/GOARCH", b.Platform)
	}
	if b.Short() == "" || !strings.HasPrefix(b.String(), "qcat ") {
		t.Errorf("Current() formatted as %q / %q", b.Short(), b.String())
	}
}
