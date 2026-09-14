#!/bin/sh
# Run on the MacBook. SCP uses your normal SSH configuration and host-key checks.
set -eu

usage() {
    printf 'Usage: %s [SSH_HOST:REMOTE_PATH]\n' "$0"
    printf 'Default source: mini:.local/bin/qcat\n'
    printf 'Installs to ~/.local/bin/qcat; does not restart running processes.\n'
}

case "${1-}" in
    -h|--help) usage; exit 0 ;;
esac
if [ "$#" -gt 1 ]; then
    usage >&2
    exit 2
fi
if [ "$(uname -s)" != Darwin ]; then
    printf 'This installer must run on macOS.\n' >&2
    exit 1
fi

source=${1-mini:.local/bin/qcat}
case "$source" in
    -*|'') printf 'Invalid SCP source.\n' >&2; exit 2 ;;
    *:*) ;;
    *) printf 'Expected SSH_HOST:REMOTE_PATH.\n' >&2; exit 2 ;;
esac
destination=${HOME:?HOME must be set}/.local/bin
mkdir -p "$destination"
# Stage on the destination filesystem so the final rename is atomic. A fresh
# inode avoids macOS's stale executable-signature cache after in-place updates.
stage=$(mktemp -d "$destination/.qcat-install.XXXXXXXX")
cleanup() {
    rm -f "$stage/qcat"
    rmdir "$stage"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

printf 'Downloading %s ...\n' "$source"
scp "$source" "$stage/qcat"
/usr/bin/lipo -verify_arch "$(uname -m)" "$stage/qcat"
chmod 755 "$stage/qcat"
# Ad-hoc signing is for local execution, not publisher authentication. Trust
# comes from the source host authenticated by SSH; do not bypass host-key checks.
/usr/bin/codesign --force --sign - "$stage/qcat"
/usr/bin/codesign --verify --strict --verbose=2 "$stage/qcat"
"$stage/qcat" --help >/dev/null
mv -f "$stage/qcat" "$destination/qcat"
printf 'Installed %s/qcat\n' "$destination"
printf 'qcat-se, identities, and peer configuration were left unchanged.\n'
printf 'Running processes still use the old binary. To restart your MacBook forwarder:\n'
printf '  launchctl kickstart -k gui/%s/com.ekarulf.qcat\n' "$(id -u)"
