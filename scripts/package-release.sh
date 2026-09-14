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
mkdir -p dist
stage=$(mktemp -d "${TMPDIR:-/tmp}/qcat-release.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
name="qcat-$target"
mkdir "$stage/$name"
GOOS=$release_os GOARCH=$release_arch CGO_ENABLED=0 \
  go build -mod=readonly -trimpath -o "$stage/$name/qcat" ./cmd/qcat
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
