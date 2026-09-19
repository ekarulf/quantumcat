# Quantumcat bootstrap v1

This pre-release definition freezes PeerID at SHA-512/256 and makes the server
sign the canonical transcript bytes with pure ML-DSA-87 instead of their
digest. The PeerID change is not identity-file- or pairing-compatible with
earlier builds. The signature change is wire-incompatible but needs no
additional re-pairing: identity keys and PeerIDs are unaffected.

Network frames: ASCII `QCAT`, version byte `1`, message-type byte, big-endian
uint16 payload length, payload. The header is eight bytes. Hard limit: 32768
bytes. Every type has an exact size; reject unknown types, versions, and trailing
bytes. All integers use big-endian encoding.

| Type | Payload, in order | Bytes |
| --- | --- | --- |
| 1 ClientHello | client PeerID (32), WG public (32), disco public (32), nonce (32), server PeerID (32), reserved zeros (32), Unix timestamp (8), KEM public (1568), signature (4627) | 6395 |
| 2 ServerHello | server PeerID (32), WG public (32), disco public (32), nonce (32), ciphertext (1568), signature (4627), server proof (48) | 6371 |
| 3 ClientFinish | transcript hash (48), client proof (48) | 96 |
| 4 ServerAccepted | transcript hash (48), acknowledgement proof (48) | 96 |

ClientHello signs its unsigned frame, whose header payload length is **1768**
(not the transmitted length 6395), with ML-DSA context
`qcat-handshake-client-v1`. Reserved bytes must be zero.
Public ML-DSA keys are 2592 bytes, obtained from the local pairing store.
PeerID is SHA-512/256 over `qcat-peer-v1` followed by that key. This derivation
is frozen independently of the wire suite. Text IDs use `qpeer:` plus unpadded
uppercase RFC 4648 base32. All 32 identifier bytes are retained.

The canonical transcript is this fixed **3483-byte** concatenation:

```text
"qcat-transcript-v1" || version_byte ||
server_peer_id || server_wg_public || server_disco_public ||
server_nonce || kem_ciphertext || complete_unsigned_client_hello
```

The complete unsigned ClientHello includes its timestamp and reserved bytes.
The transcript serves two distinct roles:

* **ServerHello signs the canonical transcript bytes themselves** with pure
  ML-DSA-87 under the application context `qcat-handshake-server-v1`. It does
  **not** sign a digest. FIPS 204 §5.4 prefers pure ML-DSA and requires an
  application-level pre-hash to provide λ bits of both collision and
  second-preimage strength. For ML-DSA-87, λ is 256, so a conventional digest
  would need at least 512 output bits to preserve the signature scheme's full
  strength.
* **The transcript hash is SHA-384 of those same bytes**, 48 bytes wide. It is
  used in HKDF info, HMAC confirmation, ClientFinish and ServerAccepted, and
  the pending and replay tables; it is not the signed message.

Because the ML-KEM shared secret is already pseudorandom, HKDF-Expand with
SHA-384 derives separate 32-byte keys directly. Its info strings are
`qcat-wireguard-psk-v2 || transcript_hash` and
`qcat-handshake-confirm-v2 || transcript_hash`. Proofs use HMAC-SHA-384 under
the confirmation key over a label followed by the transcript hash. Labels:
`server-finished`, `client-finished`, `server-accepted`.

The DERP source must equal the signed client WG key. The client checks the
server identity and transport keys against its paired descriptor. Timestamps
allow ±120 seconds. Authenticated nonces enter a five-minute replay cache.
Exact duplicate ClientHellos receive a cached response without re-encapsulation.

Pending state expires after 30 seconds, including acknowledgement retry state.
Clients have a 25-second budget and retry once per second. ClientFinish includes
the transcript hash to identify the session. Type 4 is an authenticated
acknowledgement, replacing the design's optional Error message. This handles
lost finishes without premature client peer installation. Repeated finishes
resend the acknowledgement without reinstalling a peer.
Acceptance is committed only after transport and any TUN route installation
succeed. Installation failure erases the pending keys and acknowledgement state;
repeated finishes cannot turn a failed installation into a successful handshake.

The server installs the peer after ClientFinish verification; the client waits
for ServerAccepted. Legacy Meow packets never authorize a Quantumcat peer.
Failures are silent to unauthenticated senders.

Limits: a 64-packet serialized server queue, four hellos/second per source before
the shared 64-verifications/second budget, and four new handshakes/second per
PeerID only after signature verification. Invalid signatures cannot consume
the claimed identity's quota. Token buckets refill continuously, with initial
burst capacities of 4/64/4 respectively (not strict rolling-window maxima).
Idle rate-table entries can be discarded after one second, when their buckets
would be full again. There are 256 pending handshakes (at most eight per
authenticated identity, shared across its source keys), 19,264 replay
entries, 4096 entries in each separate source/identity rate table, and 4096
installed sessions. The global budget is a resource bound, not a guarantee
against distributed denial of service. Unknown peers trigger no signature work,
encapsulation, filesystem I/O, or peer installation. Installed sessions expire
after one hour. Revocation is checked before key confirmation and during use.
CLI clients renew every 45 minutes with a fresh nonce and ephemeral ML-KEM key,
using the same WireGuard node/discovery keys. The server permits replacement of
an active node's PSK and lease only for the same authenticated PQ identity and
discovery key. Duplicate finishes only resend their acknowledgement; they never
extend a lease or reinstall an older PSK. Revoked identities cannot renew.
Selecting a finish for installation invalidates competing pending transcripts
for the same source (and erases their key material). A second installation for
that source cannot begin while the first is outstanding. Only the surviving
committed transcript may resend its cached acknowledgement.

The server updates the peer's PSK in place before acknowledging; the client
updates its PSK after the authenticated acknowledgement and schedules a fresh
WireGuard handshake on the next user packet. Existing WireGuard traffic keys
are retained through the transition. Node addresses, routes, netstack and TCP/
UDP sockets are not recreated. Failed client attempts retry after five seconds;
there is no process-lifetime deadline. Both endpoints require renewal support.

## Swift helper

Inherited stdin/stdout carry a big-endian uint32 length, one operation byte,
and payload (maximum 32768 bytes). Replies use the same framing with a status
byte (0 success, 1 error) and result. Errors are bounded UTF-8 text.

| Operation | Input | Result |
| --- | --- | --- |
| 1 GenerateIdentity | empty | opaque dataRepresentation |
| 2 LoadIdentity | dataRepresentation | empty |
| 3 GetIdentityPublicKey | empty | public key |
| 4 Sign | uint8 context length, context, message | signature |
| 5 GenerateEphemeralKEM | empty | empty |
| 6 GetKEMPublicKey | empty | public key |
| 7 Decapsulate | ciphertext | shared secret |
| 8 DestroyKEM | empty | empty |
| 9 Capabilities | empty | capability text |

Each KEM helper process owns one ephemeral key. Decapsulation discards it;
closing the process also destroys it. Persistent identity storage contains
only Apple's opaque representation, in a mode-0600 file. There is no operation
to export a Secure Enclave private key and no network listener.

## Published UDP services

`serve --udp PORT=HOST:PORT` exposes an operator-selected destination to paired
clients. The destination is never taken from a datagram. Each local sender
IP:port gets a distinct connected tunnel UDP socket.

Application datagrams are framed **inside WireGuard**, using the published UDP
port. This accommodates messages larger than Tailcat's 1232-byte payload limit;
it does not add encryption or reliability. Raw packets from another Tailcat
application are not this service protocol.

Each fragment has a 16-byte header:

| Field | Bytes |
| --- | --- |
| ASCII `QUD1` (includes framing version) | 4 |
| Datagram ID, big-endian uint64 | 8 |
| Original payload length, big-endian uint16 | 2 |
| Zero-based fragment index, big-endian uint16 | 2 |

Fragments carry up to 1056 payload bytes, so a frame is at most 1072 bytes.
All non-final fragments have exactly 1056 bytes; the final one contains exactly
the remaining length. Empty datagrams use index 0 with no payload. IDs begin
at a random 64-bit value per socket and increment per datagram. Original
payloads are limited to 65,507 bytes (at most 63 fragments).

This conservatively caps each direct-path encrypted IPv6 packet at 1200 bytes:
40 outer IPv6 + 8 outer UDP + 32 WireGuard header/tag + 1120 padded inner packet.
The inner packet contains 40 IPv6 + 8 UDP + up to 1072 framing/payload bytes.
WireGuard pads to 16-byte boundaries; the 1120-byte budget is already aligned.
Normal outer IPv4 packets are smaller. This budget covers the forwarded UDP
data path, not TCP services, network-layer extensions, or DERP/TLS stream packets.

Reassembly stores only received fragment payloads; the full output buffer is
allocated only on completion. Reassembly is per socket, handles out-of-order fragments, and ignores duplicate
fragments of incomplete datagrams. At most eight incomplete datagrams are
retained per flow. Entries have a fixed two-second deadline checked on incoming
frames; the oldest entry is evicted when capacity is reached. Idle-flow shutdown
also releases reassembly state. Invalid versions, sizes, indices, and trailing
data are dropped before allocating an assembly.

There are no acknowledgements or retries. Missing fragments cause loss of that
datagram, never delivery of a partial message. Complete duplicate datagrams may
still be delivered; the application owns replay handling. This framing does not
change the bootstrap or WireGuard protocol.
