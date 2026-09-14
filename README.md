# Quantumcat

Quantumcat (`qcat`) is a point-to-point VPN built from WireGuard, Tailscale
magicsock, and DERP, with no Tailscale account or coordination server.
ML-DSA-87 authenticates paired devices; a fresh ML-KEM-1024 exchange derives
each connection's WireGuard PSK. Endpoint descriptors contain public data only.

This is an initial implementation of [DESIGN.md](DESIGN.md), not a
security-audited release. The new bootstrap protocol needs independent
cryptographic review before protecting sensitive production traffic.

## Install a download (macOS and Linux)

Download an archive and its matching `.sha256` file from
[GitHub Releases](https://github.com/ekarulf/quantumcat/releases).
Choose `qcat-darwin-arm64.tar.gz` for Apple Silicon macOS 26+,
`qcat-linux-amd64.tar.gz` for x86-64 Linux, or `qcat-linux-arm64.tar.gz`
for ARM64 Linux. FreeBSD amd64 is also built. Intel Mac downloads are not
currently provided. Linux binaries use software keys and do not require libc.

Until a release is published, signed-in GitHub users can download artifacts from
the [Build and release workflow](https://github.com/ekarulf/quantumcat/actions/workflows/build.yml).
Unzip the artifact first to get the tarball and checksum. Builds run on main
pushes, pull requests, and manual dispatches. Prefer release/tag builds over
unreviewed pull-request artifacts.

Verify **before extracting**, using the filename you downloaded:

```sh
# macOS:
shasum -a 256 -c qcat-darwin-arm64.tar.gz.sha256
tar -xzf qcat-darwin-arm64.tar.gz
cd qcat-darwin-arm64
# Linux instead (substitute arm64 when appropriate):
# sha256sum -c qcat-linux-amd64.tar.gz.sha256
# tar -xzf qcat-linux-amd64.tar.gz
# cd qcat-linux-amd64
```

Checksums detect corruption; they are not publisher signatures. macOS binaries
are ad-hoc signed, **not** Developer ID signed or notarized. Gatekeeper may require
approval under System Settings → Privacy & Security. Only approve a download
whose source you trust; do not disable Gatekeeper globally.

From the extracted directory, install using fresh files and atomic renames
(important for macOS code-signature caching). Stop any existing supervised qcat
process before upgrading, and restart it afterward; an upgrade interrupts flows.

```sh
set -e
mkdir -p "$HOME/.local/bin"
install_stage=$(mktemp -d "$HOME/.local/bin/.qcat-install.XXXXXXXX")
install -m 755 qcat "$install_stage/qcat"
if [ "$(uname -s)" = Darwin ]; then
    install -m 755 qcat-se "$install_stage/qcat-se"
    codesign --verify --strict "$install_stage/qcat"
    codesign --verify --strict "$install_stage/qcat-se"
    mv -f "$install_stage/qcat-se" "$HOME/.local/bin/qcat-se"
fi
mv -f "$install_stage/qcat" "$HOME/.local/bin/qcat"
rmdir "$install_stage"
export PATH="$HOME/.local/bin:$PATH"
qcat --help
```

The `set -e` makes a verification failure stop installation. Add the PATH
export to your shell's startup file for future
terminals. Keep `qcat-se` beside `qcat` on macOS. Never replace an existing
identity during an upgrade. Hardware-backed identities require a supported
Secure Enclave; `qcat debug` checks capabilities. CI compiles the helper but
cannot test hardware-backed signing.

## Quick start: persistent SSH/Mosh server

Install qcat on both devices. Enable the server's existing SSH service (macOS:
System Settings → General → Sharing → Remote Login; Linux: your distribution's
OpenSSH server). Install Mosh on both devices if wanted (`brew install mosh` on
macOS, or your Linux package manager). qcat does not install or configure sshd,
SSH login keys, or Mosh for you.

### 1. Initialize and pair

On the client, once:

```sh
qcat identity init --name laptop > laptop.qpeer
```

Transfer `laptop.qpeer` to the server using an existing trusted SSH connection
or another authenticated channel. Compare full PeerIDs out of band. On the
server, as the account that will run the service:

```sh
qcat identity init --name outpost
qcat peer add laptop /path/to/laptop.qpeer
```

macOS defaults to Secure Enclave; Linux defaults to software. Do not use `sudo`
for this per-user setup. Configuration and private identity live under
`~/.config/qcat`; never transfer `identity.json`. Only `.qpeer` public files are
exchanged. If already initialized, use `qcat identity show` instead of init.

### 2a. macOS: run as a LaunchAgent

From the extracted archive, copy the template:

```sh
mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
cp deploy/macos/com.quantumcat.server.plist "$HOME/Library/LaunchAgents/"
```

Edit `~/Library/LaunchAgents/com.quantumcat.server.plist`: replace **every**
`REPLACE_HOME` with your absolute home directory, e.g. `/Users/alice`.
Launchd does not expand `~` or shell variables in these paths. Then:

```sh
plutil -lint "$HOME/Library/LaunchAgents/com.quantumcat.server.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.quantumcat.server.plist"
launchctl print "gui/$(id -u)/com.quantumcat.server"
tail -n 30 "$HOME/Library/Logs/qcat-server.log"
qcat status
```

This starts at login and retries failures every 30 seconds. A LaunchAgent is
not a pre-login system daemon; the account must be logged in. Do not load this
alongside another qcat server using the same configuration. To stop/unload:

```sh
launchctl bootout "gui/$(id -u)/com.quantumcat.server"
```

After editing the plist, boot it out and bootstrap again. Keep the Mac awake
if it must be continuously reachable.

### 2b. Linux: run as a systemd user service

From the extracted archive, as the same user who initialized the identity:

```sh
mkdir -p "$HOME/.config/systemd/user"
cp deploy/systemd/qcat.service "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now qcat.service
systemctl --user status qcat.service
journalctl --user -u qcat.service -n 30 --no-pager
qcat status
```

For startup at boot and operation after logout, an administrator can enable
lingering for this account: `sudo loginctl enable-linger "$USER"`.
Use `systemctl --user stop qcat` to stop and `systemctl --user restart qcat`
after an upgrade. `systemctl --user disable --now qcat` disables startup too.
The unit runs unprivileged, with private file creation and core dumps disabled.
This per-user setup trusts that OS account to manage its peers; it is not a
root-managed, separately isolated service account.

Both templates publish tunnel TCP 22 and UDP 60000–61000 to matching loopback
ports. They do **not** bind public host port 22 or open public UDP listeners for
Mosh. No root privileges or TUN interface are needed. Existing host firewall
rules and sshd listeners remain unchanged.

### 3. Import the server and connect

At startup the server prints a public JSON descriptor to its log (shown above).
Copy the complete JSON object, including `Endpoint`, into `outpost.qpeer` and
transfer it to the client through your trusted channel. `identity show` alone
is insufficient for the server: it does not include reachability. The service
templates intentionally omit `--export`, which refuses existing files and
would prevent automatic restarts. On the client:

```sh
qcat peer add outpost /path/to/outpost.qpeer
```

Add this to `~/.ssh/config`, **before** general `Host *` defaults, replacing the
username and absolute qcat path. Retain your normal SSH host-key verification:

```sshconfig
Host outpost
    HostName outpost
    User alice
    ProxyCommand /Users/alice/.local/bin/qcat connect outpost 22
    # Optional: use the server's already-trusted SSH hostname in known_hosts.
    # HostKeyAlias server.example.com
```

On Linux the path will typically be `/home/alice/.local/bin/qcat`.
Then `ssh outpost` or `qcat mosh outpost`. The SSH alias and qcat peer name
match here; no DNS record named outpost is required with this ProxyCommand.
SSH still authenticates your SSH key independently of qcat pairing.
Neither command needs a persistent client LaunchAgent or systemd service:
SSH owns its stream and `qcat mosh` owns its dynamically allocated UDP forwarder.
Only the server must remain running.

## Automated builds and releases

The workflow tests with the race detector and vet on Linux and macOS, then
packages macOS ARM64 (including `qcat-se`), Linux amd64/ARM64, and FreeBSD amd64.
FreeBSD is cross-compiled, not executed in CI. Each archive includes service
templates, README, license, source commit, and compiler version.

Push a `v*` tag to create a **draft** GitHub release with four tarballs,
individual `.sha256` files, and combined `SHA256SUMS`. Test on real hardware
before publishing the draft. Manual workflow runs and main pushes only upload
Actions artifacts. Nothing is published merely by installing these workflow
files locally. No signing secrets are needed; only the release job gets
`contents: write`. This follows Keystone's draft-release/checksum approach.
The macOS runner is explicitly `macos-26`, a supported
[GitHub ARM64 runner label](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

To exercise packaging locally, run `bash scripts/package-release.sh linux-amd64`
(or another supported target). macOS packaging must run on a Mac with the
macOS 26 SDK. Archives and checksum files go into ignored `dist/`.

## Build from source

Requires Go 1.27.1 or newer; Go can download the pinned toolchain automatically.

```sh
make build
# On macOS 26+ with the matching Apple SDK:
make helper
./bin/qcat debug
```

Keep `qcat-se` beside `qcat`, or set `QCAT_ENCLAVE_HELPER` to its absolute path.
The older `QCAT_SE_HELPER` name remains a fallback for existing configurations.
macOS defaults to Secure Enclave identities and ephemeral KEM keys. Capability
failures are errors; there is no automatic downgrade. Linux uses CIRCL software
keys. Explicit `--provider software` also supports development on a Mac.
Secure Enclave signature/KEM interoperability with CIRCL is hardware-tested.

To update an existing MacBook installation from the mini, run on the MacBook:

```sh
sh scripts/install-from-mini.sh
# Optional alternate source:
sh scripts/install-from-mini.sh mini:/Users/ekarulf/ws/quantumcat/bin/qcat
```

The script downloads `mini:.local/bin/qcat` via SCP, checks the CPU architecture,
ad-hoc signs and verifies it, then atomically installs into `~/.local/bin/qcat`.
It leaves `qcat-se` and configuration unchanged and does not restart processes.
Use your trusted SSH host configuration; ad-hoc signing does not authenticate
the publisher. Restart the MacBook forwarder when ready using the command printed
by the script (this interrupts that forwarder's active flows).

`make build-freebsd` cross-compiles `bin/qcat-freebsd-amd64` for FreeBSD amd64.
FreeBSD uses software identities and supports the forwarding/ProxyCommand
path; OS-TUN mode is currently limited to macOS and Linux. The FreeBSD binary
has also been smoke-tested on FreeBSD 14.5 amd64 (startup and local status),
including operation under the rc.d daemon below.

### FreeBSD daemon

`deploy/freebsd/qcat` is an rc.d service using FreeBSD's `daemon(8)` supervisor.
For a **fresh installation**, install the binary as root-owned
`/usr/local/bin/qcat`, then run as root:

```sh
sh scripts/setup-freebsd-daemon.sh deploy/freebsd/qcat rotom
```

The installer refuses existing qcat accounts/configuration rather than replacing
them. It creates a non-login `qcat` user/group, generates a software identity
locally, enables boot startup, and starts the service. The process publishes TCP
22 and UDP 60000–61000 to matching loopback ports inside the authenticated tunnel;
it does not open host listeners on those ports. Its supervisor restarts failures
after five seconds; intentional `service qcat stop` stops supervision too.

- `/usr/local/etc/qcat`: `root:qcat`, 0750.
- `identity.json`: `qcat:qcat`, 0600; never copy this private file to clients.
- `peers/`: root-owned, group-readable; the daemon cannot change authorizations.
- `run/`: `qcat:qcat`, 0700; local control socket is 0600.
- `/usr/local/etc/rc.d/qcat`: `root:wheel`, 0555.
- `/var/log/qcat/qcat.log`: `root:wheel`, 0600. Core dumps are disabled.

Authorize a public client identity as root, then make it readable by the daemon:

```sh
qcat --config /usr/local/etc/qcat peer add macbook /path/to/macbook.qpeer
chown root:qcat /usr/local/etc/qcat/peers/macbook.qpeer
chmod 0640 /usr/local/etc/qcat/peers/macbook.qpeer
service qcat status
qcat --config /usr/local/etc/qcat status
```

Peers are reloaded automatically; no restart is needed after pairing. The client
also needs the server's public descriptor including its endpoint. The daemon
prints this public descriptor to its root-readable log at startup.

## Pair and forward SSH

Configuration defaults to `~/.config/qcat` or `$XDG_CONFIG_HOME/qcat`.
Override with `--config DIR` before the command, or `QCAT_CONFIG_DIR`.
Flags for each command precede positional arguments.

Client:

```sh
./bin/qcat identity init --name macbook > macbook.qpeer
```

Server, after receiving the client's public file:

```sh
./bin/qcat identity init --name outpost --provider software
./bin/qcat peer add macbook macbook.qpeer
./bin/qcat serve --tcp 22=localhost:22 --export outpost.qpeer
```

Transfer public files through an authenticated, out-of-band channel and compare
the full PeerIDs with their device owners. Importing a key grants authorization.
The server's exported file includes public DERP reachability information.

Client, after receiving the server's exported file:

```sh
./bin/qcat peer add outpost outpost.qpeer
./bin/qcat forward outpost 2222:localhost:22
# Another terminal:
ssh -p 2222 localhost
```

Local listeners bind to loopback. Each repeatable `--tcp PORT=HOST:PORT`
publishes a tunnel port and permits that exact forwarding target. Port 1 is
reserved for the authenticated CONNECT service. No inbound public port is needed.
Duplicate published TCP ports are rejected, just like duplicate UDP ports.

`identity show` prints the public identity again. `peer list`,
`peer show NAME`, and `peer remove NAME` manage pairing. Removal moves the
file to `.qpeer.revoked` for recovery. Running servers reload pairing and remove
the device's active WireGuard sessions within approximately two seconds.
Malformed peer configuration fails closed.

Configuration and peer directories must be owned by root or the running user
and not writable by group/others; the same integrity checks apply to peer files.
Group-readable root-managed files (0750 directories, 0640 peers) are supported.
Identity files additionally forbid all group/other permissions. Symlinked
identity/peer files and symlinked config/peer directories are rejected.
Reload errors revoke all authorizations and report the offending file to stderr;
identical errors are logged only once, and recovery is reported. Correct the
file and the daemon reloads it automatically; stale authorizations are not kept.

## SOCKS and streams

```sh
# Server:
./bin/qcat serve --allow-target example.com:443 --export outpost.qpeer
# Client:
./bin/qcat socks --listen 127.0.0.1:1080 outpost
curl --socks5-hostname 127.0.0.1:1080 https://example.com/

# Pipe stdin/stdout to a published TCP port:
./bin/qcat connect outpost 22
```

SOCKS5 CONNECT destinations must exactly match a server `--allow-target` or
published TCP target. DNS resolves on the server. SOCKS UDP ASSOCIATE is not
implemented; use UDP forwarding below or IP mode.
Export refuses to overwrite existing files. Use a new filename for changed
reachability and re-pair the client after removing its old entry.

## UDP forwarding and Mosh

Publish an explicit UDP destination on the server, then forward a local UDP
port to that published tunnel port. This needs neither root nor a TUN interface.

```sh
# Mac mini: forward tunnel UDP port 60001 to the loopback Mosh server.
./bin/qcat serve --udp 60001=127.0.0.1:60001 --export outpost.qpeer
# Client, after pairing the exported descriptor:
./bin/qcat forward --udp outpost 60001:60001
```

The client binds `127.0.0.1:60001`. The second number is the **published tunnel
port**, not a destination chosen by the client. Only server-configured
`--udp PORT=HOST:PORT` mappings can be reached. Repeat `--udp` for more ports;
TCP and UDP services can coexist, including on the same numeric port.
UDP mappings do not authorize TCP/SOCKS access to their destinations.

Publish Mosh's automatic port range with:

```sh
qcat serve --tcp 22=127.0.0.1:22 --udp 60000:61000=127.0.0.1:60000
```

Ranges are inclusive. `FIRST:LAST=HOST:BASE` maps each tunnel port to the
corresponding consecutive destination port starting at BASE. The example maps
60000–61000 to exactly the same ports on loopback, only for authenticated peers.
Overlapping mappings and destination ranges extending past 65535 are rejected.

### One-command Mosh sessions

With Mosh installed on both machines, `qcat mosh` bootstraps over SSH, parses
the session key, owns a loopback UDP forwarder, and launches `mosh-client`:

```sh
# MacBook; uses the mini SSH alias (including its configured ProxyCommand).
qcat mosh mini
# Optional different SSH alias:
qcat mosh --ssh-host mini-qcat mini
```

The SSH destination defaults to the peer name. The remote executable is found
via PATH, then `/opt/homebrew/bin/mosh-server`, then `/usr/local/bin/mosh-server`.
Use `--mosh-server /custom/path/mosh-server` to override discovery.

By default, `mosh-server` chooses the remote port; the wrapper reads it from
`MOSH CONNECT` and forwards to that same published tunnel port. No `-p` is passed
to `mosh-server`. The OS selects a free local loopback UDP port and the wrapper
holds its socket open, avoiding a probe/close/rebind race or conflicts with an
existing 60001 LaunchAgent. Use `--local-port 60010` to request a fixed client port.
Only existing server mappings can be used; this command does not publish ports.
Mosh normally chooses from 60000–61000, so those ports need corresponding
loopback mappings for unrestricted automatic selection. A server publishing
only 60001 does **not** support arbitrary server-selected ports. For that limited
configuration, explicitly use `--server-port 60001` to constrain Mosh instead.
The remote `mosh-server` binds to `127.0.0.1`, and the server mapping must target
that machine's corresponding loopback port. All three ports may differ:

```sh
# Example server mapping (add to its other serve options):
qcat serve --udp 61001=127.0.0.1:60002
# Client:
qcat mosh --ssh-host mini-qcat --server-port 60002 --tunnel-port 61001 --local-port 60010 mini
# Optional remote command, with arguments preserved:
qcat mosh --ssh-host mini-qcat mini -- tmux new-session -A -s main
```

Each simultaneous session needs a different **remote** Mosh port and a matching
published mapping; automatic selection lets Mosh find an available remote port.
An explicitly requested fixed port must be free. `--mosh-server` is an executable path, not a shell
command; configure SSH options in `~/.ssh/config`. The session key is passed only
via `MOSH_KEY`, never command-line arguments, status, or bootstrap logs.

The forwarder inherits qcat's wake recovery and stops when `mosh-client` exits.
`qcat status` shows it as `mosh-LOCALPORT-PEER`; `qcat down` can stop that exact
runtime (or all sessions for a peer). Startup has a two-minute SSH timeout.
If bootstrap succeeds but the client never connects, Mosh's own initial timeout
cleans up the remote session; the wrapper does not kill remote processes by PID.
See the [upstream mosh-server documentation](https://github.com/mobile-shell/mosh/blob/master/man/mosh-server.1).

Each local sender IP:port gets a separate remote UDP socket. Both sides cap
active forwarding flows at 128. Client queues retain at most three pending
datagrams per flow and drop the oldest on overflow. Flows close after two minutes
without activity; override either command with `--udp-idle-timeout 5m`.
A subsequent datagram creates a new flow and may change the source port seen
by the destination. Prefer matching timeouts on both ends.

Datagrams, including empty ones, retain their boundaries. Larger messages use
bounded fragmentation/reassembly inside WireGuard. Each fragment carries at most
1056 application bytes, keeping the encrypted direct-path IP packet within 1200
bytes even with normal IPv6/UDP headers and WireGuard padding. The same
fragment size applies to IPv4: its normal outer packet is at most 1180 bytes.
This is a forwarded-UDP data budget, not a cap on other traffic or relay TLS records.
There is no retransmission or ordering layer: a lost fragment loses the whole
datagram. The protocol limit is 65,507 bytes; OS socket limits can be smaller,
and applications should prefer small packets.

`qcat down outpost` stops its forwarders; status entries are named
`forward-udp-LOCALPORT-outpost`. Different local UDP ports and a TCP forwarder
can run for the same peer. Clients refresh authentication in process every
45 minutes, before the server's one-hour lease expires. Renewal keeps the
WireGuard node, addresses, routes, and application sockets intact, including
ProxyCommand SSH sessions. There is no scheduled client exit.

## IP mode

IP mode uses an OS TUN and only IPv6 host routes to authenticated peers.
The private prefix is `fd7a:7163:6174::/48`; host addresses derive from WireGuard
public keys. Client addresses change on each invocation. No default route,
subnet route, or DNS configuration is installed.

```sh
# Initialize and pair identities in these directories first.
sudo ./bin/qcat --config /etc/qcat serve --tun --export /tmp/outpost.qpeer
sudo ./bin/qcat --config /path/to/client-config up outpost
```

Commands print their interfaces and IPv6 addresses. Use the remote address
with ordinary applications. macOS uses `utun`, `ifconfig`, and `route`;
Linux uses TUN and requires `iproute2`. Network administration privileges are
required. Key storage is owned by the initializing account; verify Secure Enclave
access under the account used to run IP mode.

The IP packet path is tested with in-memory TUN interfaces and a local DERP
relay. Privileged route creation on physical macOS/Linux hosts has not been
exercised by the automated suite.

## Runtime control

Commands run in the foreground. Ctrl-C closes the transport and its routes.
Status/shutdown use mode-0600 Unix sockets in a mode-0700 runtime directory
inside the selected configuration.

```sh
./bin/qcat status
./bin/qcat down outpost
./bin/qcat down serve
```

`down` without a name stops all active commands using that configuration.
Use the running process's OS account, including `sudo` when applicable.
Status includes peer and direct/relay information, never private keys or PSKs.
Server authentication leases expire after one hour unless renewed. All client
commands, including `connect`, renew every 45 minutes using a fresh signed
ML-KEM exchange. Failures are retried after five seconds without intentionally
closing existing flows. Revocation and prolonged inability to renew still
prevent access; renewal does not guarantee survival of arbitrary outages.
Both endpoints need a renewal-capable build. Upgrading or restarting a running
process itself is not seamless, so update before starting long-lived sessions.
Clients also check the encrypted data path every 30 seconds (10-second timeout).
A failed check or a wall-clock gap over 15 seconds triggers network-path refresh
and fresh authentication, with five-second retries while offline. This detects
sleep even when the OS pauses its monotonic clock. Recovery retains local
listeners, the client identity, and the TCP stack; an SSH connection whose remote
TCP state has already timed out cannot be resurrected. UDP can resume after the
server lease expires without restarting the forwarder.
If an identity helper dies or a signing operation times out, the next signing
attempt starts a fresh helper, reloads the same opaque Enclave reference, and
checks its public key against the original. Existing tunnels remain intact.
Ephemeral KEM helpers are never reopened; failed handshakes generate fresh keys.
A Mac mini LaunchAgent template is provided
in `deploy/com.ekarulf.qcat-server.plist`; adapt its absolute paths before use.

Peer-targeted shutdown uses explicit runtime metadata, not name suffixes.
An exact runtime name takes precedence over a peer of the same name. For
processes started with older binaries, use their full runtime name from
`qcat status` or restart them before using peer-targeted shutdown.

## DERP and tests

`serve --region ID` selects a region; `--derp-map URL` selects another map.
Defaults use Tailcat's map and automatic region selection. The chosen region
is embedded in the descriptor. Follow the relay operator's terms or run your own.
DERP is not trusted for authentication or session confidentiality.

```sh
make test
go vet ./...
# Optional Apple hardware test:
QCAT_TEST_ENCLAVE=1 QCAT_ENCLAVE_HELPER="$PWD/bin/qcat-se" \
  go test ./internal/crypto/provider/se -v
```

Tests cover tampering, identity/source binding, expiration, replay, fresh PSKs,
lost handshake packets, rejection of legacy Meow authorization, encrypted TCP
and IP transport, revocation, storage permissions, SOCKS policy, and local control.
UDP tests also cover loopback forwarding through WireGuard, isolated senders,
empty and fragmented packets, reassembly bounds, idle cleanup, and unpublished
destination rejection.

Known test caveat: forcing relay-only operation with
`TS_DEBUG_ALWAYS_USE_DERP=true` completes the UDP traffic checks but currently
hangs in the pinned networking dependency's shutdown (blocked dummy UDP
receivers). That forced-relay test is not a clean pass.

The pinned [Tailcat library subset](third_party/tailcat/QUANTUMCAT.md) supplies
networking with bootstrap, PSK, and TUN hooks. [PROTOCOL.md](PROTOCOL.md) specifies
the wire format and design refinements. Local configuration uses JSON; network
and helper messages use binary framing.

Go cannot guarantee compiler-resistant erasure. Pending secrets are cleared
on expiration/shutdown, KEM handles are destroyed on client exit, and PSKs remain
in the active WireGuard endpoint for the session lifetime. Persistent identity
compromise alone does not reveal old session PSKs.
