# Quantumcat

Repository: `github.com/ekarulf/quantumcat`
CLI: `qcat`

## 1. Overview

Quantumcat is a small, control-plane-free, point-to-point VPN built on Tailscale's open-source data-plane components.

It reuses:

* WireGuard for the encrypted tunnel
* Tailscale `magicsock` for UDP transport and NAT traversal
* DERP for rendezvous and relay fallback
* Tailscale/gVisor netstack where useful
* Apple's Secure Enclave for hardware-backed post-quantum client identity and ephemeral key establishment
* ML-DSA-87 for post-quantum device authentication, always pure (never pre-hashed)
* ML-KEM-1024 for post-quantum session-secret establishment
* SHA-384 for the transcript digest, HKDF and HMAC key confirmation
* SHA-512/256 for stable PeerIDs, frozen independently of the wire suite

Quantumcat should remain philosophically close to Tailcat:

> No Tailscale control plane, no account, no PKI service, no centralized coordination database, and no requirement for an inbound public port.

Tailcat already demonstrates that WireGuard, `magicsock`, DERP, and gVisor netstack can be assembled into a control-plane-free peer-to-peer transport. Tailcat initially connects through DERP and upgrades to direct UDP when NAT traversal succeeds.

Quantumcat changes the **peer authentication and WireGuard PSK bootstrap**.

---

# 2. Goals

Quantumcat v1 should provide:

1. Point-to-point private networking.
2. No Tailscale account or coordination server.
3. No shared bearer secret embedded in an address.
4. Hardware-backed identity on supported Apple clients.
5. Post-quantum authentication.
6. Post-quantum protection for recorded WireGuard traffic.
7. Fresh key material for every connection.
8. Direct UDP connectivity whenever possible.
9. DERP fallback when direct connectivity is impossible.
10. No inbound port-forwarding requirement.
11. Per-device authorization and revocation.
12. A small protocol surface.
13. A mostly-Go implementation.
14. No custom packet-encryption protocol.
15. No custom VPN cryptography beyond a small authenticated key-bootstrap protocol.

The project should prefer existing cryptographic constructions and libraries rather than implementing primitives.

---

# 3. Non-goals

Quantumcat v1 is **not**:

* a replacement for the full Tailscale control plane
* a multi-user identity provider
* an OAuth/OIDC system
* a certificate authority
* a general mesh-management service
* an ACL engine
* a DNS service
* an exit-node management platform
* an enterprise device-management system
* a new WireGuard protocol
* a new encryption algorithm

The initial design should optimize for:

```text
one trusted device <--> one trusted server
```

Multiple authorized clients may connect to one server, but arbitrary transitive mesh routing is not required for v1.

The architecture should not prevent adding mesh functionality later.

---

# 4. Why not use stock Tailcat authentication?

Tailcat already provides almost all of the desired networking substrate.

Its current connection descriptor can contain:

* server WireGuard public key
* server discovery public key
* DERP information
* a 256-bit WireGuard preshared key

The PSK makes the Tailcat address itself a bearer capability. Tailcat explicitly warns that an address containing the PSK must be treated as secret. Tailcat also supports explicit allowed client node keys when an address is public.

Quantumcat should instead separate:

```text
reachability information
```

from:

```text
authorization
```

A Quantumcat endpoint descriptor may safely contain public information.

Possession of the descriptor must not grant access.

---

# 5. High-level architecture

```text
                         DERP
                     rendezvous/relay
                         /     \
                        /       \
                       /         \
              ┌───────▼───┐   ┌─▼─────────┐
              │   Client  │   │   Server   │
              │           │   │            │
              │ magicsock │   │ magicsock  │
              └─────┬─────┘   └────┬───────┘
                    │              │
                    └──── UDP ─────┘
                         direct
                       when possible

                           │
                           │
                      WireGuard
                           │
                    ML-KEM-derived
                         PSK
```

The networking path remains standard WireGuard over `magicsock`.

Quantumcat adds a bootstrap protocol before installing the WireGuard peer.

---

# 6. Cryptographic design

## 6.1 Long-lived identity

Each Quantumcat peer has a long-lived ML-DSA-87 identity.

On supported Apple devices:

```text
Secure Enclave
     │
     └── ML-DSA-87 private identity key
```

The private identity key never leaves the Secure Enclave.

The public identity key is the Quantumcat device identity.

Apple exposes `SecureEnclave.MLDSA87.PrivateKey`, including signing and persistent `dataRepresentation` support.

On Linux or platforms without a Secure Enclave, use a software ML-DSA-87 key with strict filesystem permissions.

Use Go's `crypto/mldsa` implementation with the ML-DSA-87 parameter set. New
software identities persist the standard library's 32-byte seed encoding.

### Identity ID

Define:

```text
PeerID = SHA-512/256(
    "qcat-peer-v1" ||
    canonical_ml_dsa_87_public_key
)
```

Display the ID in a human-friendly encoding such as:

```text
qpeer:7CJ3-2FPG-...
```

Internally retain all 32 bytes.

This PeerID derivation is frozen independently of the wire-protocol version.
Protocol-suite upgrades do not change an identity's PeerID.

Do not use a truncated identifier as the authorization key.

---

# 7. Per-connection ML-KEM key

For every new connection, the client creates a **fresh ML-KEM-1024 keypair**.

On supported Apple devices:

```text
SecureEnclave.MLKEM1024.PrivateKey
```

The private key exists only for this connection.

Apple exposes hardware-backed ML-KEM-1024 generation and decapsulation through CryptoKit.

Although Apple does not expose Secure Enclave ML-KEM through the `OneTimePrivateKey` API, a normal Secure Enclave ML-KEM private key can still be generated for a single connection and discarded after use. Apple explicitly documents the Secure Enclave variant as the persistent/hardware-backed ML-KEM API.

This provides the PQ session secret.

---

# 8. Why use both ML-DSA and ML-KEM?

The two algorithms have separate responsibilities.

```text
ML-DSA-87
    │
    └── "Which device is this?"

ML-KEM-1024
    │
    └── "What fresh secret protects this connection?"

WireGuard
    │
    └── "How are packets transported securely?"
```

This is preferable to treating an ML-KEM public key itself as a permanent identity.

Signatures provide explicit authentication.

KEM provides session secrecy.

WireGuard remains responsible for packet protection, replay handling, counters, rekeying, and transport encryption.

---

# 9. Forward secrecy

The ML-KEM key generated by the client is ephemeral.

Connection:

```text
generate ephemeral ML-KEM-1024 key
             │
             ▼
      perform encapsulation
             │
             ▼
        derive WG PSK
             │
             ▼
destroy ephemeral KEM private key
```

After the private key is destroyed, later compromise of the client's persistent ML-DSA identity key does not reveal the old ML-KEM secret.

Therefore recorded historical WireGuard sessions remain protected from later compromise of the signing identity.

This is an important design invariant.

---

# 10. WireGuard keys

Do not modify WireGuard.

Quantumcat should use normal Tailscale/WireGuard node keys.

For the initial implementation:

### Server

The server may retain a stable WireGuard node key because Tailcat/DERP reachability is keyed around the server's node identity.

### Client

Generate an ephemeral WireGuard node key for each process invocation or connection.

The ML-DSA handshake binds the WireGuard keys to the authenticated Quantumcat identities.

The security model therefore does **not** rely solely on the classical WireGuard public keys.

---

# 11. WireGuard PSK

WireGuard has an existing 256-bit preshared-key input.

Quantumcat should place the ML-KEM-derived secret there.

Conceptually:

```text
ML-KEM-1024 shared secret
            │
            ▼
       labeled HKDF
            │
            ▼
        32-byte PSK
            │
            ▼
         WireGuard
```

Do not patch the WireGuard handshake.

Do not insert ML-KEM directly into WireGuard packets.

This keeps Quantumcat's changes outside WireGuard itself.

---

# 12. Handshake

Use a small protocol carried over the same DERP bootstrap path Tailcat currently uses for `Meow`/`Meowed`.

Tailcat's current discovery message carries the client's node public key and discovery public key, after which the server adds the peer to WireGuard.

Quantumcat changes that sequence so that the server **does not add the WireGuard peer until PQ authentication completes**.

---

# 13. ClientHello

The client generates:

```text
client_nonce       = random 32 bytes
client_wg_key      = fresh WireGuard node key
client_disco_key   = fresh/derived discovery key
client_kem_key     = fresh Secure Enclave ML-KEM-1024 key
```

Then construct:

```text
ClientHello {
    magic
    version

    client_peer_id

    client_wg_public
    client_disco_public

    client_mlkem_public

    client_nonce

    server_peer_id

    timestamp

    signature
}
```

The signature is ML-DSA-87 over a canonical encoding of all fields except `signature`.

Use an explicit signature context:

```text
"qcat-handshake-client-v1"
```

Where supported by the implementation.

The signature binds:

* the client identity
* the target server identity
* the ephemeral KEM key
* the WireGuard key
* the discovery key
* the connection nonce
* protocol version
* handshake freshness

An intercepted ClientHello cannot be repurposed toward another server.

---

# 14. Server processing

On receiving ClientHello:

```text
1. Check fixed magic.
2. Check protocol version.
3. Check total packet size.
4. Parse with bounded allocations.
5. Look up client_peer_id.
6. Reject unknown peers.
7. Check timestamp/freshness.
8. Apply rate limiting.
9. Verify ML-DSA-87 signature.
10. Only then perform ML-KEM encapsulation.
```

This order is intentional.

An unauthenticated Internet/DERP sender should not be able to induce expensive post-quantum work beyond a signature verification.

The server must **not configure WireGuard yet**.

---

# 15. Server encapsulation

Once ClientHello is authenticated, the server performs:

```text
(shared_secret, kem_ciphertext) =
    MLKEM1024.Encapsulate(client_mlkem_public)
```

Use Go's `crypto/mlkem` ML-KEM-1024 implementation.

Generate:

```text
server_nonce = random 32 bytes
```

Build the canonical transcript bytes, then compute the transcript hash.

---

# 16. Transcript

Canonical transcript:

```text
TranscriptV1 =
    protocol_version ||
    server_peer_id ||
    server_wg_public ||
    server_disco_public ||
    server_nonce ||
    kem_ciphertext ||
    complete_unsigned_client_hello
```

The canonical transcript bytes are:

```text
transcript_bytes =
    "qcat-transcript-v1" ||
    CanonicalEncode(TranscriptV1)
```

Hash:

```text
transcript_hash =
    SHA-384(transcript_bytes)
```

These values have separate consumers:

| Value | Width | Consumed by |
| --- | --- | --- |
| `transcript_bytes` | 3483 | the server's pure ML-DSA-87 signature only |
| `transcript_hash` | 48 | HKDF info, HMAC confirmation, ClientFinish and ServerAccepted payloads, pending and replay keys |

The server signs the canonical bytes rather than their digest. FIPS 204 §5.4
prefers pure ML-DSA and requires an application-level digest to provide at
least λ bits of both collision and second-preimage strength. For ML-DSA-87,
λ is 256, so preserving its full strength with a conventional hash digest
would require at least 512 output bits. SHA-384 remains the transcript digest
for the separate key-schedule, confirmation and session-state uses above.

Never concatenate variable-length fields without explicit lengths or canonical serialization.

Recommended serialization:

```text
CBOR deterministic encoding
```

or a manually specified fixed binary encoding.

Do not use JSON for the wire protocol.

---

# 17. PSK derivation

ML-KEM produces a shared secret.

Derive:

```text
wireguard_psk = HKDF-SHA384-Expand(
    mlkem_shared_secret,
    "qcat-wireguard-psk-v2" || transcript_hash,
    32
)

handshake_key = HKDF-SHA384-Expand(
    mlkem_shared_secret,
    "qcat-handshake-confirm-v2" || transcript_hash,
    32
)
```

Erase the raw ML-KEM shared secret as soon as practical.

The 32-byte `wireguard_psk` becomes the WireGuard preshared key.

---

# 18. ServerHello

Server returns:

```text
ServerHello {
    version

    server_peer_id

    server_wg_public
    server_disco_public

    server_nonce

    kem_ciphertext

    server_signature

    server_proof
}
```

`server_signature` is a pure ML-DSA-87 signature over `transcript_bytes` — the
canonical transcript itself, not `transcript_hash`.

Use context:

```text
"qcat-handshake-server-v1"
```

`server_proof` is:

```text
HMAC-SHA384(
    handshake_key,
    "server-finished" || transcript_hash
)
```

The signature authenticates the server identity.

The HMAC proves that the server possesses the ML-KEM-generated shared secret.

---

# 19. Client processing

The client:

```text
1. Verify server_peer_id matches configured peer.
2. Rebuild transcript_bytes from the received ServerHello and its own hello.
3. Verify the pure ML-DSA-87 server signature over transcript_bytes.
4. Send kem_ciphertext to Secure Enclave ML-KEM decapsulation.
5. Receive shared secret.
6. Compute transcript_hash = SHA-384(transcript_bytes).
7. Derive wireguard_psk.
8. Derive handshake_key.
9. Verify server_proof.
```

Only after all checks pass may the client configure its WireGuard peer.

---

# 20. ClientFinish

The client sends:

```text
ClientFinish {
    transcript_hash
    client_proof
}
```

where:

```text
client_proof =
    HMAC-SHA384(
        handshake_key,
        "client-finished" || transcript_hash
    )
```

The server verifies the proof.

Only then does the server add the client to its WireGuard peer configuration.

This gives explicit mutual key confirmation.

---

# 21. Final connection sequence

```text
Client                                      Server
  │                                            │
  │ generate ephemeral:                       │
  │ - WireGuard key                           │
  │ - ML-KEM-1024 key in Secure Enclave       │
  │                                            │
  │ ML-DSA signed ClientHello                 │
  ├───────────────────────────────────────────►│
  │                                            │
  │                           lookup PeerID    │
  │                           check freshness │
  │                           verify ML-DSA   │
  │                                            │
  │                           encapsulate to  │
  │                           ephemeral KEM   │
  │                                            │
  │             ServerHello + KEM ct          │
  │             + ML-DSA signature            │
  │             + key confirmation            │
  │◄───────────────────────────────────────────┤
  │                                            │
  │ Secure Enclave decapsulates               │
  │ derive WG PSK                             │
  │ verify server signature + proof           │
  │                                            │
  │ ClientFinish                              │
  ├───────────────────────────────────────────►│
  │                                            │
  │                           verify proof     │
  │                                            │
  │ configure WireGuard peers on both ends    │
  │                                            │
  │════════════ WireGuard handshake ══════════│
  │                                            │
  │════════ encrypted IP traffic ═════════════│
  │                                            │
  │       magicsock attempts direct UDP        │
  │       DERP remains fallback                │
```

---

# 22. Security properties

## 22.1 No bearer-secret endpoint address

The connection descriptor contains public routing information only.

Publishing it does not authorize a connection.

---

## 22.2 Hardware-backed client identity

On Apple hardware, the persistent ML-DSA private key lives in the Secure Enclave.

Malware which can read normal files should not obtain the raw identity key.

---

## 22.3 Hardware-backed ephemeral PQ secret

On Apple hardware, the ML-KEM-1024 decapsulation private key also lives in the Secure Enclave.

---

## 22.4 Post-quantum authentication

Client and server identity authentication uses ML-DSA-87 rather than P-256, Ed25519, RSA, or another classical signature scheme.

---

## 22.5 Post-quantum recorded-traffic protection

The WireGuard PSK depends on an ML-KEM-1024 shared secret.

An attacker recording WireGuard traffic and later obtaining a cryptographically relevant quantum computer cannot recover the PSK merely by attacking WireGuard's X25519 exchange.

---

## 22.6 PQ forward secrecy

Because the ML-KEM client private key is freshly generated for the connection and destroyed afterwards, later compromise of the persistent device identity key does not reveal previous session PSKs.

---

## 22.7 Classical + PQ defense in depth

The resulting WireGuard session depends on:

```text
WireGuard X25519
       +
ML-KEM-1024 PSK
```

A failure of ML-KEM does not remove WireGuard's normal security.

A future quantum break of X25519 does not remove the ML-KEM-derived PSK.

---

# 23. Threat model

Assume attackers may:

* know the server's Quantumcat address
* connect to public DERP servers
* know authorized PeerIDs
* observe DERP traffic
* observe all Internet traffic
* replay bootstrap messages
* inject arbitrary bootstrap packets
* scan continuously
* possess large amounts of commodity compute
* archive traffic for future cryptanalysis

Do not assume DERP is trusted for confidentiality or authentication.

The security protocol must remain end-to-end.

---

# 24. Out of scope threats

v1 does not attempt to defend against:

* compromise of the running endpoint OS while the tunnel is active
* malicious kernel/root on the endpoint
* physical attacks defeating the Secure Enclave
* vulnerabilities in WireGuard itself
* vulnerabilities in Apple's Secure Enclave implementation
* compromise of both endpoints while session secrets are resident in memory

---

# 25. Replay resistance

ClientHello contains:

```text
timestamp
client_nonce
target server identity
```

Server should accept a narrow window, initially:

```text
±120 seconds
```

Maintain a short in-memory replay cache:

```text
SHA384(client_peer_id || client_nonce)
```

for approximately five minutes.

Duplicate ClientHello messages should receive either:

```text
same cached response
```

or:

```text
silent drop
```

Do not perform another encapsulation for a duplicate.

---

# 26. Denial-of-service handling

All handshake messages must have hard size limits.

Processing order:

```text
cheap length checks
        ↓
version check
        ↓
known PeerID lookup
        ↓
timestamp check
        ↓
rate limit
        ↓
ML-DSA verification
        ↓
ML-KEM encapsulation
```

Never perform:

* filesystem writes
* external network calls
* cloud API calls
* ML-KEM encapsulation
* WireGuard configuration

for unknown peers.

Rate limits should exist:

```text
per DERP source/node key
per client PeerID
global
```

Do not trust an IP address alone because DERP may hide the original path.

---

# 27. No KMS dependency

The earlier KMS concept is intentionally **not** part of Quantumcat.

Quantumcat should establish sessions without:

* AWS credentials
* KMS
* cloud API calls
* cloud authorization
* per-connection billing
* cloud availability dependency

That design remains useful for a separate TCP gate, but it is unnecessary for this VPN.

---

# 28. Endpoint descriptor

Define a public Quantumcat endpoint descriptor.

Example logical structure:

```text
Endpoint {
    version

    server_peer_id

    server_identity_public_key

    server_wireguard_public_key
    server_disco_public_key

    derp_region
    optional_derp_map
}
```

Because ML-DSA public keys are large, the short human token should preferably contain:

```text
server_peer_id
server WG key
server disco key
DERP information
```

and obtain the full server ML-DSA public key from a local peer configuration established during pairing.

Do not put the entire ML-DSA public key into every short connection token.

---

# 29. Pairing

Pairing is out-of-band.

Provide:

```bash
qcat identity show
```

Output:

```text
Peer: macbook
PeerID: qpeer:...
ML-DSA-87: ...
```

Server:

```bash
qcat peer add macbook ./macbook.qpeer
```

Client:

```bash
qcat peer add outpost ./outpost.qpeer
```

A `.qpeer` file should be a public descriptor.

Suggested contents:

```text
version
name
peer_id
ml_dsa_87_public_key
optional endpoint/rendezvous information
```

It contains no secret.

Later convenience mechanisms may include:

```text
qcat peer export --qr
qcat peer scan
```

but QR pairing is not required for v1.

---

# 30. Configuration layout

Suggested:

```text
~/.config/qcat/
    config.toml

    identities/
        default.ref

    peers/
        outpost.qpeer
        macbook.qpeer
```

Server:

```text
/etc/qcat/
    config.toml
    identity.key
    peers/
```

On macOS, `identity.ref` stores only the Secure Enclave key representation/reference required to reopen the key.

Apple exposes `dataRepresentation` and a corresponding initializer for Secure Enclave ML-KEM private keys.

Protect this representation using Keychain or filesystem permissions as appropriate, but do not treat it as equivalent to an exportable raw private key.

---

# 31. macOS Secure Enclave architecture

Keep the main application in Go.

Do not rewrite networking in Swift.

Use:

```text
qcat
 │
 ├── Go
 │    ├── protocol
 │    ├── magicsock
 │    ├── WireGuard
 │    ├── DERP
 │    ├── routing
 │    └── CLI
 │
 └── qcat-se
      └── Swift
           └── CryptoKit
                └── Secure Enclave
```

For v1, prefer a small **Swift helper process** rather than relying on unstable Swift-to-C export attributes.

The helper communicates only over inherited stdin/stdout or an inherited Unix socket.

Do not expose a network listener.

---

# 32. `qcat-se` interface

Use a small framed binary protocol.

Operations:

```text
GenerateIdentity
LoadIdentity
GetIdentityPublicKey
Sign

GenerateEphemeralKEM
GetKEMPublicKey
Decapsulate
DestroyKEM
Capabilities
```

Example conceptual requests:

```text
CapabilitiesRequest {}
```

returns:

```text
CapabilitiesResponse {
    secure_enclave: true
    ml_dsa_87: true
    ml_kem_1024: true
}
```

Generate identity:

```text
GenerateIdentityRequest {
    label
}
```

returns:

```text
identity_reference
public_key
```

Generate KEM:

```text
GenerateEphemeralKEMRequest {}
```

returns:

```text
handle
public_key
```

Decapsulate:

```text
DecapsulateRequest {
    handle
    ciphertext
}
```

returns:

```text
shared_secret
```

Then immediately destroy the handle.

The helper must never provide an operation that exports a Secure Enclave private key.

---

# 33. Swift implementation

Conceptual implementation:

```swift
let identity =
    try SecureEnclave.MLDSA87.PrivateKey(...)

let kem =
    try SecureEnclave.MLKEM1024.PrivateKey.generate()

let publicKey = kem.publicKey

let secret =
    try kem.decapsulate(ciphertext)
```

Use the actual APIs exposed by the SDK targeted during implementation rather than duplicating assumptions from this document.

Availability must be runtime checked.

If the host lacks the required Secure Enclave APIs, return a clear capability error.

Do not silently downgrade to classical P-256.

---

# 34. Software provider

Create a generic Go abstraction:

```go
type IdentityProvider interface {
    PublicKey(ctx context.Context) ([]byte, error)
    Sign(ctx context.Context, contextLabel string, msg []byte) ([]byte, error)
}

type KEMProvider interface {
    Generate(ctx context.Context) (KEMHandle, []byte, error)
    Decapsulate(
        ctx context.Context,
        h KEMHandle,
        ciphertext []byte,
    ) ([]byte, error)
    Destroy(ctx context.Context, h KEMHandle) error
}
```

Implementations:

```text
internal/crypto/provider/se
internal/crypto/provider/software
```

Software implementation uses Go's `crypto/mldsa` and `crypto/mlkem` packages.

macOS implementation uses `qcat-se`.

This makes protocol tests platform-independent.

---

# 35. Go crypto dependencies

Use the Go standard library for:

```text
ML-KEM-1024
ML-DSA-87
SHA-512/256 for stable PeerIDs
SHA-384
HMAC-SHA-384
HKDF-Expand
crypto/rand
```

Do not implement ML-KEM or ML-DSA directly.

---

# 36. Tailcat integration

Start by importing or forking the Tailcat package rather than reconstructing Tailscale networking from scratch.

Tailcat already has:

```text
Server
ConnInfo
DERP bootstrap
magicsock
netstack
WireGuard configuration
Meow/Meowed discovery
TCP forwarding
UDP support
exit-node support
```

Tailcat v0.6.0 currently includes TCP and UDP functionality and its PSK-enabled WireGuard transport.

Quantumcat should initially track the upstream Tailcat package.

Avoid a hard fork unless extension points prove insufficient.

---

# 37. Bootstrap protocol integration

Replace:

```text
Meow
    ↓
immediately authorize WG peer
```

with:

```text
QHello
    ↓
PQ authentication
    ↓
QServerHello
    ↓
QFinish
    ↓
authorize WG peer
```

The relevant Tailcat discovery code currently lives around `disco.go`, where `EncodeMeowPing`, `ParseMeowPing`, and `EncodeMeowed` implement the current bootstrap framing.

Quantumcat should implement its own packet prefix to avoid ambiguity.

For example:

```text
0x51 0x43 0x41 0x54
```

ASCII:

```text
QCAT
```

Followed by:

```text
version
message_type
length
payload
```

---

# 38. Message types

```text
0x01 ClientHello
0x02 ServerHello
0x03 ClientFinish
0x04 Error
```

Errors sent to unauthenticated clients should reveal very little.

Prefer silent drop for:

```text
unknown PeerID
bad signature
malformed packet
replay
rate limit
```

Detailed errors may be logged locally.

---

# 39. Maximum sizes

Set explicit constants.

Do not infer limits dynamically from attacker-controlled values.

For example:

```text
MaxHandshakePacket = 32 KiB
MaxIdentityKey     = implementation-specific constant
MaxKEMPublicKey    = implementation-specific constant
MaxKEMCiphertext   = implementation-specific constant
MaxSignature       = implementation-specific constant
```

Validate against Go/Apple's expected exact sizes where possible.

Reject trailing unexpected bytes.

---

# 40. VPN modes

Implement in phases.

## Phase 1: Tailcat-compatible transport

Support:

```bash
qcat serve
qcat forward
qcat socks
```

This proves:

* PQ handshake
* DERP bootstrap
* WireGuard PSK integration
* NAT traversal
* authentication
* Secure Enclave bridge

before adding system routing.

## Phase 2: point-to-point TUN

Add:

```bash
qcat up outpost
```

Result:

```text
client                     server

100.100.x.2/32             100.100.x.1/32
      │                           │
     TUN                         TUN
      │                           │
      └────── WireGuard ──────────┘
```

Use a private ULA IPv6 prefix or another explicitly configured range rather than colliding with real Tailscale addressing.

Prefer IPv6 internally because point-to-point address management is simpler.

Example:

```text
fd7a:7163:6174::/48
```

but choose the final prefix deliberately before release.

---

# 41. Routing

Initial `qcat up` should only install a host route to the remote Quantumcat peer.

Example:

```text
qcat up outpost
```

creates:

```text
fdxx::1 -> qcat tunnel
```

Do not initially implement:

```text
0.0.0.0/0
::/0
LAN subnet routing
DNS interception
```

Later:

```bash
qcat up outpost --route 10.0.0.0/24
```

can enable subnet routing.

---

# 42. CLI

Target interface:

```bash
qcat identity init
qcat identity show

qcat peer add
qcat peer remove
qcat peer list
qcat peer show

qcat serve
qcat connect
qcat forward
qcat socks
qcat up
qcat down
qcat status
qcat debug
```

Examples:

```bash
qcat identity init --name macbook
```

```bash
qcat peer add outpost outpost.qpeer
```

```bash
qcat up outpost
```

```bash
qcat forward outpost 2222:localhost:22
```

```bash
ssh localhost -p 2222
```

---

# 43. Server configuration

Example:

```toml
[identity]
name = "outpost"

[derp]
region = "auto"

[network]
address = "fdxx::1"

[[peers]]
name = "erik-macbook"
file = "/etc/qcat/peers/erik-macbook.qpeer"
address = "fdxx::2"
```

Client:

```toml
[identity]
name = "macbook"
provider = "secure-enclave"

[[peers]]
name = "outpost"
file = "~/.config/qcat/peers/outpost.qpeer"
address = "fdxx::1"
```

---

# 44. Private-key storage

## macOS

Persistent ML-DSA identity:

```text
Secure Enclave
```

Persist only the representation/reference needed to reopen it.

Prefer Keychain storage.

Ephemeral ML-KEM key:

```text
memory/Secure Enclave only
```

Do not persist it.

## Linux server

Store ML-DSA private identity key:

```text
/var/lib/qcat/identity.key
```

permissions:

```text
0600
```

owned by the dedicated `qcat` service account.

Later support may include:

* TPM
* PKCS#11
* Nitro Enclaves
* HSM
* Linux kernel keyring

None are required for v1.

---

# 45. Privilege separation

The network daemon should run with the minimum privileges required.

Where possible:

```text
qcat daemon
    │
    ├── networking process
    │
    └── key helper
```

The macOS Secure Enclave helper should perform only:

* key generation
* public-key retrieval
* signing
* decapsulation

It should not:

* open network sockets
* parse DERP
* configure routes
* process WireGuard packets

---

# 46. Secret erasure

Go cannot guarantee perfect compiler-resistant memory zeroization.

Still:

* limit lifetime of shared secrets
* overwrite byte buffers wher
