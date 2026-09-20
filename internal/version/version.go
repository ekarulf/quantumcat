// Package version reports which build of qcat is running.
//
// Release builds inject a tag at link time. Everything else is described from
// the VCS metadata the Go toolchain stamps into every binary it compiles from a
// checkout, so a plain `go build` or `go install` still self-reports usefully
// with no build tooling, no generated files, and no repository state baked into
// source.
package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// Version is the release version. Tagged builds set it at link time:
//
//	go build -ldflags "-X github.com/ekarulf/quantumcat/internal/version.Version=v1.2.3"
//
// Leave it empty for development builds; Current then derives a description
// from build metadata instead.
var Version string

// devel names a build that was not produced from a release tag.
const devel = "devel"

// Build identifies a binary. Revision and Time are zero when the toolchain
// recorded no VCS metadata, which is the case for module-proxy installs and for
// builds from an unpacked source archive.
type Build struct {
	Version  string    // release tag, or "devel"
	Revision string    // full commit hash, when known
	Time     time.Time // commit time, when known
	Dirty    bool      // the checkout had uncommitted changes
	Go       string    // toolchain that compiled the binary
	Platform string    // GOOS/GOARCH
}

// Current describes the running binary.
func Current() Build {
	b := Build{Version: Version, Go: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH}
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				b.Revision = s.Value
			case "vcs.time":
				b.Time, _ = time.Parse(time.RFC3339, s.Value)
			case "vcs.modified":
				b.Dirty = s.Value == "true"
			}
		}
	}
	if b.Version != "" {
		return b
	}
	// A binary compiled from a checkout carries VCS stamps and a synthetic
	// pseudo-version derived from the last tag; reporting that pseudo-version
	// would dress an arbitrary commit up as a release, so call it "devel" and
	// let the revision identify it. A module-proxy install carries no stamps
	// but does carry the genuine version it was installed at, which is worth
	// reporting verbatim.
	if ok && b.Revision == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		b.Version = info.Main.Version
	} else {
		b.Version = devel
	}
	return b
}

// Short is a one-line identity, suitable for a help banner. It names the commit
// only for development builds, where the tag alone would not identify anything.
func (b Build) Short() string {
	s := b.Version
	if b.Version == devel && b.Revision != "" {
		s += " " + b.Revision[:min(12, len(b.Revision))]
	}
	if b.Dirty {
		s += " (modified)"
	}
	return s
}

// String is the multi-line detail printed by `qcat --version`.
func (b Build) String() string {
	var s strings.Builder
	s.WriteString("qcat " + b.Short() + "\n")
	if b.Revision != "" {
		s.WriteString("commit    " + b.Revision + "\n")
	}
	if !b.Time.IsZero() {
		s.WriteString("committed " + b.Time.UTC().Format(time.RFC3339) + "\n")
	}
	s.WriteString("go        " + b.Go + " " + b.Platform + "\n")
	return s.String()
}
