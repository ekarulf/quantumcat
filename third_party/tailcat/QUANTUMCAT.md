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
