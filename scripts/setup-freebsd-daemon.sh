#!/bin/sh
# Run as root on a fresh FreeBSD server, with the rc.d template as argument 1.
# Existing identities/services are refused rather than overwritten.
set -eu
umask 077
[ "$(uname -s)" = FreeBSD ] && [ "$(id -u)" = 0 ] || {
    echo 'Run this setup as root on FreeBSD.' >&2; exit 1;
}
[ "$#" = 2 ] || { echo 'Usage: setup-freebsd-daemon.sh RC_TEMPLATE PEER_NAME' >&2; exit 2; }
template=$1
peer_name=$2
[ -f "$template" ] && [ -x /usr/local/bin/qcat ] || exit 1
for path in /usr/local/etc/qcat /usr/local/etc/rc.d/qcat /var/run/qcat /var/log/qcat; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        echo "Refusing to overwrite existing $path" >&2
        exit 1
    fi
done
if pw usershow qcat >/dev/null 2>&1 || pw groupshow qcat >/dev/null 2>&1; then
    echo 'Refusing to reuse an existing qcat user/group without review.' >&2
    exit 1
fi
sh -n "$template"
pw groupadd qcat
pw useradd qcat -g qcat -d /nonexistent -s /usr/sbin/nologin -w no -c 'Quantumcat daemon'
install -d -o root -g qcat -m 0750 /usr/local/etc/qcat /usr/local/etc/qcat/peers
install -d -o qcat -g qcat -m 0700 /usr/local/etc/qcat/run
# Generate on the server. Only public identity output is discarded; private
# material is written directly into identity.json, never copied through SSH.
/usr/local/bin/qcat --config /usr/local/etc/qcat identity init --name "$peer_name" --provider software >/dev/null
chown qcat:qcat /usr/local/etc/qcat/identity.json
chmod 0600 /usr/local/etc/qcat/identity.json
install -o root -g wheel -m 0555 "$template" /usr/local/etc/rc.d/qcat
sysrc qcat_enable=YES
service qcat start
echo 'qcat installed and enabled. No client identities have been authorized.'
