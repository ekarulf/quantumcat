# Upstream provenance

Networking library subset from github.com/tailscale/tailcat main,
commit 72411995d2aabc795742be66db951eeb5fb9ce25. BSD-3-Clause license retained.
Optional SSH/file-server and CLI code is omitted.

Quantumcat modifications add a bounded DERP bootstrap callback, disable Meow
authorization when that callback is configured, gate client WireGuard peer
configuration until authentication, and support per-client PSKs. Additional
hooks expire/revoke peers, expose local status, and support a real TUN with
host-only peer filtering. Addresses use fd7a:7163:6174::/48. Review these
changes against the pinned upstream commit when updating.

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
