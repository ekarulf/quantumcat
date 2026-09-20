#!/usr/bin/env bash
# Run from the repository root. No secrets or signing credentials required.
set -euo pipefail
target=${1:?usage: bash scripts/package-release.sh OS-ARCH}
case "$target" in
  darwin-arm64|linux-amd64|linux-arm64|freebsd-amd64) ;;
  *) echo "unsupported target: $target" >&2; exit 1 ;;
esac
release_os=${target%-*}
release_arch=${target#*-}
# VERSION stamps a release tag into the binary. Unset, the build still records
# the commit through the toolchain's own VCS stamping and reports "devel", so
# this script needs no repository history beyond the checked-out commit.
version=${VERSION:-}
ldflags=""
if [[ -n $version ]]; then
  ldflags="-X github.com/ekarulf/quantumcat/internal/version.Version=$version"
fi
mkdir -p dist
stage=$(mktemp -d "${TMPDIR:-/tmp}/qcat-release.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
name="qcat-$target"
mkdir "$stage/$name"
GOOS=$release_os GOARCH=$release_arch CGO_ENABLED=0 \
  go build -mod=readonly -trimpath -ldflags "$ldflags" -o "$stage/$name/qcat" ./cmd/qcat
if [[ $release_os == darwin ]]; then
  # A macOS 26 SDK is required; no Secure Enclave is needed to compile.
  xcrun swiftc -O -target arm64-apple-macosx26.0 \
    -module-cache-path "$stage/swift-cache" \
    -o "$stage/$name/qcat-se" swift/qcat-se.swift
  codesign --force --sign - "$stage/$name/qcat"
  codesign --force --sign - "$stage/$name/qcat-se"
  codesign --verify --strict "$stage/$name/qcat"
  codesign --verify --strict "$stage/$name/qcat-se"
fi
if [[ $(go env GOHOSTOS)-$(go env GOHOSTARCH) == "$target" ]]; then
  "$stage/$name/qcat" --help > /dev/null
  stamped=$("$stage/$name/qcat" version)
  # The linker silently ignores -X for a symbol it cannot find, so a renamed
  # package or variable would produce an unversioned release without any build
  # failure. Confirm the tag actually reached the binary.
  if [[ -n $version && $stamped != *"$version"* ]]; then
    echo "binary does not report VERSION=$version:" >&2
    echo "$stamped" >&2
    exit 1
  fi
  echo "$stamped" >&2
fi
cp README.md LICENSE "$stage/$name/"
cp -R deploy "$stage/$name/"
mkdir "$stage/$name/scripts"
cp scripts/setup-freebsd-daemon.sh "$stage/$name/scripts/"
git rev-parse HEAD > "$stage/$name/BUILD_COMMIT"
go version > "$stage/$name/BUILD_TOOLCHAIN"
tar -czf "dist/$name.tar.gz" -C "$stage" "$name"
(
  cd dist
  if command -v sha256sum >/dev/null; then
    sha256sum "$name.tar.gz" > "$name.tar.gz.sha256"
  else
    shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256"
  fi
)
