# Quantumcat

Quantumcat (`qcat`) is a point-to-point VPN built from WireGuard, Tailscale
magicsock, and DERP, with no Tailscale account or coordination server.
ML-DSA-87 authenticates paired devices; a fresh ML-KEM-1024 exchange derives
each connection's WireGuard PSK. Endpoint descriptors contain public data only.

This is an initial implementation of [DESIGN.md](DESIGN.md), not a
security-audited release. The new bootstrap protocol needs independent
cryptographic review before protecting sensitive production traffic.

## Build

Requires Go 1.27.1 or newer; Go can download the pinned toolchain automatically.

```sh
make build
# On macOS 26+ with the matching Apple SDK:
make helper
./bin/qcat debug
```

Keep `qcat-se` beside `qcat`, or set `QCAT_SE_HELPER` to its absolute path.
macOS defaults to Secure Enclave identities and ephemeral KEM keys. Capability
failures are errors; there is no automatic downgrade. Linux uses CIRCL software
keys. Explicit `--provider software` also supports development on a Mac.
Secure Enclave signature/KEM interoperability with CIRCL is hardware-tested.

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

`identity show` prints the public identity again. `peer list`,
`peer show NAME`, and `peer remove NAME` manage pairing. Removal moves the
file to `.qpeer.revoked` for recovery. Running servers reload pairing and remove
the device's active WireGuard sessions within approximately two seconds.
Malformed peer configuration fails closed.

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

For an existing Mosh launcher, replace the wsudp data path with this forwarder
and keep the SSH bootstrap/session-key exchange. Start the remote Mosh server
on the mapped loopback port and direct the local Mosh client to the forwarder's
loopback port. A normal `mosh localhost` invocation would try to bootstrap SSH
on the client itself; it is not a replacement for the remote bootstrap.

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
can run for the same peer. The existing one-hour session limit still applies:
**automatic renewal is not implemented yet**, so this change alone does not
make long-lived Mosh sessions seamless.

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
Sessions expire after one hour; restart the client for fresh authentication.
Automatic renewal and background service installation are not included.

## DERP and tests

`serve --region ID` selects a region; `--derp-map URL` selects another map.
Defaults use Tailcat's map and automatic region selection. The chosen region
is embedded in the descriptor. Follow the relay operator's terms or run your own.
DERP is not trusted for authentication or session confidentiality.

```sh
make test
go vet ./...
# Optional Apple hardware test:
QCAT_TEST_SE=1 QCAT_SE_HELPER="$PWD/bin/qcat-se" \
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
