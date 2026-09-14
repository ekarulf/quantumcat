# Upstream provenance

Networking library subset from github.com/tailscale/tailcat v0.6.0,
commit 790406204c002a6f109ef7c6a30a436601a1f6a8. BSD-3-Clause license retained.
Optional SSH/file-server and CLI code is omitted.

Quantumcat modifications add a bounded DERP bootstrap callback, disable Meow
authorization when that callback is configured, gate client WireGuard peer
configuration until authentication, and support per-client PSKs. Additional
hooks expire/revoke peers, expose local status, and support a real TUN with
host-only peer filtering. Addresses use fd7a:7163:6174::/48. Review these
changes against the pinned upstream tag when updating.

Authenticated installation now reports success/failure to the bootstrap layer
before acknowledgements are sent. Failed installs roll back peer/network-map
state and invalidate protocol acceptance retry state.

Client.RefreshNetwork rebinds outer sockets and refreshes path discovery without
replacing the device or application sockets. Client.Probe checks encrypted TSMP
round trips with bounded-by-context retries; qcat uses these for wake/outage recovery.

Renewal updates an existing peer's PSK and validity callback in place, checks
its PQ identity owner and discovery key, and retains active WireGuard traffic
keys and sockets. Client.Renew schedules a fresh WireGuard handshake after
installing the acknowledged PSK; it does not recreate the device or netstack.
