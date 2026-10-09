# Upstream provenance

Networking library subset from github.com/tailscale/tailcat main,
commit 52fbad323e9d352f1febb623e0975368e9a8cbdd. BSD-3-Clause license retained.
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

The upstream AllowClient hook also gates authenticated peer installation.
DisconnectClient clears authentication, PSK, and validity state, synchronizes
the WireGuard device, and removes real-TUN peer routes through OnTunnelPeer.
The local module manifest is tidied for the retained networking subset.

Authenticated admission hooks run off the bootstrap worker with one pending
decision per key and at most 64 pending decisions. Expiry and renewal continue
while a hook is blocked; shutdown rejects pending installs without waiting for
the hooks. Install, disconnect, eviction, and expiry serialize peer state and
route callbacks so a removed peer cannot acquire a late route.
Legacy admissions retain their per-key slot until the hook returns, and reject
stale approval after disconnect or shutdown. A fresh retry consults the policy
again after the cancelled hook has finished.
