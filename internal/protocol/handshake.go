package protocol

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"iter"
	"sync"
	"time"

	"github.com/ekarulf/quantumcat/internal/crypto/provider"
)

var ErrRejected = errors.New("handshake rejected")

func derive(ss []byte, hash [hashSize]byte) (psk, confirmation [32]byte, err error) {
	prk, err := hkdf.Extract(sha512.New384, ss, []byte("qcat-handshake-extract-v1"))
	if err != nil {
		return psk, confirmation, err
	}
	defer clear(prk)
	p, err := hkdf.Expand(sha512.New384, prk, "qcat-wireguard-psk-v3"+string(hash[:]), 32)
	if err != nil {
		return psk, confirmation, err
	}
	defer clear(p)
	c, err := hkdf.Expand(sha512.New384, prk, "qcat-handshake-confirm-v3"+string(hash[:]), 32)
	if err != nil {
		return psk, confirmation, err
	}
	defer clear(c)
	copy(psk[:], p)
	copy(confirmation[:], c)
	return psk, confirmation, nil
}
func proof(k [32]byte, label string, hash [hashSize]byte) []byte {
	m := hmac.New(sha512.New384, k[:])
	m.Write([]byte(label))
	m.Write(hash[:])
	return m.Sum(nil)
}

type Client struct {
	identity     provider.Identity
	kem          provider.KEM
	hello        []byte
	server       PeerID
	serverPublic []byte
	keys         Keys
	ack          []byte
}

func NewClient(ctx context.Context, identity provider.Identity, newKEM provider.NewKEM, serverPublic []byte, local, remote Keys, now time.Time) (*Client, []byte, error) {
	if len(serverPublic) != mldsa.MLDSA87PublicKeySize {
		return nil, nil, ErrRejected
	}
	pub, err := identity.PublicKey(ctx)
	if err != nil {
		return nil, nil, err
	}
	kem, err := newKEM(ctx)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*Client, []byte, error) { kem.Destroy(); return nil, nil, err }
	kp, err := kem.PublicKey(ctx)
	if err != nil {
		return fail(err)
	}
	if len(kp) != mlkem.EncapsulationKeySize1024 {
		return fail(ErrRejected)
	}
	id, sid := ID(pub), ID(serverPublic)
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return fail(err)
	}
	stamp := make([]byte, 8)
	binary.BigEndian.PutUint64(stamp, uint64(now.Unix()))
	// Send a nonce-blinded tag rather than the stable PeerID. The signature below
	// still covers the tag, so the server's transcript binds whatever was sent.
	tag := peerTag(id, nonce)
	hello := join(tag[:], local.WG[:], local.Disco[:], nonce, sid[:], make([]byte, 32), stamp, kp)
	sig, err := identity.Sign(ctx, ClientContext, frame(ClientHello, hello))
	if err != nil {
		return fail(err)
	}
	c := &Client{identity: identity, kem: kem, hello: hello, server: sid, serverPublic: append([]byte(nil), serverPublic...), keys: remote}
	return c, frame(ClientHello, join(hello, sig)), nil
}
func (c *Client) Close() { c.kem.Destroy() }
func (c *Client) Complete(ctx context.Context, packet []byte) ([32]byte, []byte, error) {
	var zero [32]byte
	kind, b, err := Parse(packet)
	if err != nil || kind != ServerHello {
		return zero, nil, ErrRejected
	}
	if !hmac.Equal(b[:32], c.server[:]) || !hmac.Equal(b[32:64], c.keys.WG[:]) || !hmac.Equal(b[64:96], c.keys.Disco[:]) {
		return zero, nil, ErrRejected
	}
	ct := b[128 : 128+mlkem.CiphertextSize1024]
	tb, hash := transcript(c.hello, c.server, c.keys, b[96:128], ct)
	sigEnd := len(b) - proofSize
	if !verify(c.serverPublic, ServerContext, tb, b[128+mlkem.CiphertextSize1024:sigEnd]) {
		return zero, nil, ErrRejected
	}
	ss, err := c.kem.Decapsulate(ctx, ct)
	if err != nil {
		return zero, nil, err
	}
	defer clear(ss)
	psk, hk, err := derive(ss, hash)
	if err != nil {
		return zero, nil, err
	}
	defer clear(psk[:])
	defer clear(hk[:])
	if !hmac.Equal(proof(hk, "server-finished", hash), b[sigEnd:]) {
		clear(psk[:])
		return zero, nil, ErrRejected
	}
	c.kem.Destroy()
	c.ack = frame(ServerAccepted, join(hash[:], proof(hk, "server-accepted", hash)))
	return psk, frame(ClientFinish, join(hash[:], proof(hk, "client-finished", hash))), nil
}
func (c *Client) Accepted(packet []byte) bool { return len(c.ack) > 0 && hmac.Equal(c.ack, packet) }

type Session struct {
	Peer PeerID
	Keys Keys
	PSK  [32]byte
	// Installed must be called exactly once after transport installation. Failure
	// invalidates retry state; success permits cached acceptance acknowledgements.
	Installed func(bool)
}
type pending struct {
	session    Session
	hash       [hashSize]byte
	hk         [32]byte
	source     [32]byte
	expires    time.Time
	accepted   bool
	installing bool
	helloHash  [hashSize]byte
	response   []byte
}
type bucket struct {
	start  time.Time
	tokens float64
}
type Server struct {
	mu       sync.Mutex
	Identity provider.Identity
	Public   []byte
	Keys     Keys
	// Authorized enumerates each authorized peer's full PeerID and ML-DSA public
	// key. It must be served from memory and must omit revoked peers: handshake
	// processing performs no filesystem enumeration or parsing. Protocol code
	// only reads the set; it never retains or mutates it.
	Authorized iter.Seq2[PeerID, []byte]
	pending    map[[hashSize]byte]*pending
	replay     map[[hashSize]byte]time.Time
	limits     map[[32]byte]bucket
	peerLimits map[[32]byte]bucket
	global     bucket
}

// Expire erases pending secrets even when the server receives no traffic.
func (s *Server) Expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, p := range s.pending {
		if !now.Before(p.expires) {
			clear(p.hk[:])
			clear(p.session.PSK[:])
			delete(s.pending, h)
		}
	}
	for h, t := range s.replay {
		if !now.Before(t) {
			delete(s.replay, h)
		}
	}
	for _, limits := range []map[[32]byte]bucket{s.limits, s.peerLimits} {
		for h, t := range limits {
			if now.Sub(t.start) > time.Second {
				delete(limits, h)
			}
		}
	}
}
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, p := range s.pending {
		clear(p.hk[:])
		clear(p.session.PSK[:])
		delete(s.pending, h)
	}
	clear(s.replay)
	clear(s.limits)
	clear(s.peerLimits)
}

func allow(b bucket, now time.Time, max int) (bucket, bool) {
	if b.start.IsZero() {
		b = bucket{start: now, tokens: float64(max)}
	} else if now.After(b.start) {
		b.tokens = min(float64(max), b.tokens+now.Sub(b.start).Seconds()*float64(max))
		b.start = now
	}
	if b.tokens < 1 {
		return b, false
	}
	b.tokens--
	return b, true
}

// Handle is serialized and bounds all caches. No work or state is allocated for
// unknown identities, and encapsulation follows authentication and replay checks.
func (s *Server) Handle(ctx context.Context, source [32]byte, packet []byte, now time.Time) ([]byte, *Session) {
	kind, b, err := Parse(packet)
	if err != nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, p := range s.pending {
		if !now.Before(p.expires) {
			clear(p.hk[:])
			clear(p.session.PSK[:])
			delete(s.pending, h)
		}
	}
	for h, t := range s.replay {
		if !now.Before(t) {
			delete(s.replay, h)
		}
	}
	for _, limits := range []map[[32]byte]bucket{s.limits, s.peerLimits} {
		for h, t := range limits {
			if now.Sub(t.start) > time.Second {
				delete(limits, h)
			}
		}
	}
	if kind == ClientFinish {
		h := [hashSize]byte(b[:hashSize])
		p := s.pending[h]
		if p == nil || p.source != source || len(Lookup(s.Authorized, p.session.Peer)) == 0 || !hmac.Equal(proof(p.hk, "client-finished", h), b[hashSize:]) {
			return nil, nil
		}
		ack := frame(ServerAccepted, join(h[:], proof(p.hk, "server-accepted", h)))
		if p.accepted {
			return ack, nil
		}
		if p.installing {
			return nil, nil
		}
		// Only one installation may be outstanding per transport source.
		// Discard competing transcripts before handing a PSK to the transport;
		// otherwise a delayed finish could roll back a completed renewal.
		for _, other := range s.pending {
			if other != p && other.source == source && other.installing && !other.accepted {
				return nil, nil
			}
		}
		for key, other := range s.pending {
			if other != p && other.source == source {
				clear(other.hk[:])
				clear(other.session.PSK[:])
				delete(s.pending, key)
			}
		}
		session := p.session
		p.installing = true
		var once sync.Once
		session.Installed = func(ok bool) {
			once.Do(func() {
				s.mu.Lock()
				defer s.mu.Unlock()
				if s.pending[h] != p {
					return
				}
				clear(p.session.PSK[:])
				if ok {
					p.accepted = true
				} else {
					clear(p.hk[:])
					delete(s.pending, h)
				}
			})
		}
		return ack, &session
	}
	if kind != ClientHello {
		return nil, nil
	}
	// Version 1 assigns no semantics to the reserved bytes. The complete hello
	// is transcript-bound, but non-zero extensions still require a new version.
	if source != [32]byte(b[32:64]) || [32]byte(b[64:96]) == [32]byte{} || PeerID(b[128:160]) != ID(s.Public) || [32]byte(b[160:192]) != [32]byte{} {
		return nil, nil
	}
	stamp := int64(binary.BigEndian.Uint64(b[192:200]))
	if stamp < now.Unix()-120 || stamp > now.Unix()+120 {
		return nil, nil
	}
	var ok bool
	if s.limits == nil {
		s.limits = make(map[[32]byte]bucket)
		s.peerLimits = make(map[[32]byte]bucket)
	}
	if _, exists := s.limits[source]; !exists && len(s.limits) >= 4096 {
		evictOldest(s.limits)
	}
	// Charge a sender's quota before the identity scan and the shared
	// verification budget. Claimed identities must not consume another device's
	// quota before authentication.
	s.limits[source], ok = allow(s.limits[source], now, 4)
	if !ok {
		return nil, nil
	}
	// The first 32 bytes are a nonce-blinded tag, not the client's PeerID, so
	// recover the real identity by recomputing each authorized peer's tag. One
	// HMAC per authorized peer is far cheaper than the ML-DSA verification it
	// gates, and the source bucket above bounds how often an unauthenticated
	// sender can trigger the scan. Everything downstream uses the real PeerID.
	id, pub := s.resolve(b[:32], b[96:128])
	if len(pub) == 0 || ID(pub) != id {
		return nil, nil
	}
	s.global, ok = allow(s.global, now, 64)
	if !ok {
		return nil, nil
	}
	replay := sha512.Sum384(join(id[:], b[96:128]))
	if _, ok := s.replay[replay]; ok {
		digest := sha512.Sum384(packet)
		for _, p := range s.pending {
			if p.source == source && p.helloHash == digest {
				return append([]byte(nil), p.response...), nil
			}
		}
		return nil, nil
	}
	// Replay retention covers the full global token budget over five minutes,
	// including its initial burst. Pending work also has an identity quota.
	if len(s.replay) >= 64*301 || len(s.pending) >= 256 {
		return nil, nil
	}
	hello := b[:helloSize]
	if !verify(pub, ClientContext, frame(ClientHello, hello), b[helloSize:]) {
		return nil, nil
	}
	if _, exists := s.peerLimits[[32]byte(id)]; !exists && len(s.peerLimits) >= 4096 {
		evictOldest(s.peerLimits)
	}
	s.peerLimits[[32]byte(id)], ok = allow(s.peerLimits[[32]byte(id)], now, 4)
	if !ok {
		return nil, nil
	}
	owned := 0
	for _, p := range s.pending {
		if p.session.Peer == id {
			owned++
		}
	}
	if owned >= 8 {
		return nil, nil
	}
	kp, err := mlkem.NewEncapsulationKey1024(hello[200:])
	if err != nil {
		return nil, nil
	}
	ss, ct := kp.Encapsulate()
	defer clear(ss)
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil
	}
	sid := ID(s.Public)
	tb, hash := transcript(hello, sid, s.Keys, nonce, ct)
	psk, hk, err := derive(ss, hash)
	if err != nil {
		return nil, nil
	}
	defer clear(psk[:])
	defer clear(hk[:])
	sig, err := s.Identity.Sign(ctx, ServerContext, tb)
	if err != nil {
		clear(psk[:])
		clear(hk[:])
		return nil, nil
	}
	if s.pending == nil {
		s.pending = make(map[[hashSize]byte]*pending)
		s.replay = make(map[[hashSize]byte]time.Time)
	}
	response := frame(ServerHello, join(sid[:], s.Keys.WG[:], s.Keys.Disco[:], nonce, ct, sig, proof(hk, "server-finished", hash)))
	s.pending[hash] = &pending{session: Session{Peer: id, Keys: Keys{[32]byte(b[32:64]), [32]byte(b[64:96])}, PSK: psk}, hash: hash, hk: hk, source: source, expires: now.Add(30 * time.Second), helloHash: sha512.Sum384(packet), response: response}
	s.replay[replay] = now.Add(5 * time.Minute)
	return response, nil
}

// resolve maps a blinded client peer tag back to the authorized identity that
// produced it, returning the zero PeerID and nil when nothing matches. Matching
// a tag proves nothing on its own: it only selects which ML-DSA public key the
// signature must verify against.
func (s *Server) resolve(tag, nonce []byte) (PeerID, []byte) {
	if s.Authorized == nil {
		return PeerID{}, nil
	}
	for id, pub := range s.Authorized {
		if candidate := peerTag(id, nonce); hmac.Equal(candidate[:], tag) {
			return id, pub
		}
	}
	return PeerID{}, nil
}

func evictOldest(table map[[32]byte]bucket) {
	var oldestKey [32]byte
	var oldest time.Time
	for key, value := range table {
		if oldest.IsZero() || value.start.Before(oldest) {
			oldestKey, oldest = key, value.start
		}
	}
	if !oldest.IsZero() {
		delete(table, oldestKey)
	}
}
