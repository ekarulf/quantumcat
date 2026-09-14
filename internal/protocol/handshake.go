package protocol

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/ekarulf/quantumcat/internal/crypto/provider"
)

var ErrRejected = errors.New("handshake rejected")

func derive(ss []byte, hash [32]byte) (psk, confirmation [32]byte) {
	prk, _ := hkdf.Extract(sha256.New, ss, hash[:])
	defer clear(prk)
	p, _ := hkdf.Expand(sha256.New, prk, "qcat-wireguard-psk-v1", 32)
	c, _ := hkdf.Expand(sha256.New, prk, "qcat-handshake-confirm-v1", 32)
	copy(psk[:], p)
	copy(confirmation[:], c)
	clear(p)
	clear(c)
	return
}
func proof(k [32]byte, label string, hash [32]byte) []byte {
	m := hmac.New(sha256.New, k[:])
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
	if len(serverPublic) != mldsa87.PublicKeySize {
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
	if len(kp) != mlkem1024.PublicKeySize {
		return fail(ErrRejected)
	}
	id, sid := ID(pub), ID(serverPublic)
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return fail(err)
	}
	stamp := make([]byte, 8)
	binary.BigEndian.PutUint64(stamp, uint64(now.Unix()))
	hello := join(id[:], local.WG[:], local.Disco[:], nonce, sid[:], make([]byte, 32), stamp, kp)
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
	ct := b[128 : 128+mlkem1024.CiphertextSize]
	hash := transcript(c.hello, c.server, c.keys, b[96:128], ct)
	sigEnd := len(b) - 32
	if !verify(c.serverPublic, ServerContext, hash[:], b[128+mlkem1024.CiphertextSize:sigEnd]) {
		return zero, nil, ErrRejected
	}
	ss, err := c.kem.Decapsulate(ctx, ct)
	if err != nil {
		return zero, nil, err
	}
	defer clear(ss)
	psk, hk := derive(ss, hash)
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
	hash, hk   [32]byte
	source     [32]byte
	expires    time.Time
	accepted   bool
	installing bool
	helloHash  [32]byte
	response   []byte
}
type bucket struct {
	start time.Time
	count int
}
type Server struct {
	mu       sync.Mutex
	Identity provider.Identity
	Public   []byte
	Keys     Keys
	// Lookup must use the full PeerID and return nil for revoked/unknown peers.
	Lookup     func(PeerID) []byte
	pending    map[[32]byte]*pending
	replay     map[[32]byte]time.Time
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
	if now.Sub(b.start) >= time.Second || b.start.IsZero() {
		b = bucket{start: now}
	}
	b.count++
	return b, b.count <= max
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
			if now.Sub(t.start) > time.Minute {
				delete(limits, h)
			}
		}
	}
	if kind == ClientFinish {
		h := [32]byte(b[:32])
		p := s.pending[h]
		if p == nil || p.source != source || len(s.Lookup(p.session.Peer)) == 0 || !hmac.Equal(proof(p.hk, "client-finished", h), b[32:]) {
			return nil, nil
		}
		ack := frame(ServerAccepted, join(h[:], proof(p.hk, "server-accepted", h)))
		if p.accepted {
			return ack, nil
		}
		if p.installing {
			return nil, nil
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
	id := PeerID(b[:32])
	pub := s.Lookup(id)
	if len(pub) == 0 || ID(pub) != id || source != [32]byte(b[32:64]) || [32]byte(b[64:96]) == [32]byte{} || PeerID(b[128:160]) != ID(s.Public) || [32]byte(b[160:192]) != [32]byte{} {
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
		return nil, nil
	}
	// Charge a sender's quota before the shared verification budget. Claimed
	// identities must not consume another device's quota before authentication.
	s.limits[source], ok = allow(s.limits[source], now, 4)
	if !ok {
		return nil, nil
	}
	s.global, ok = allow(s.global, now, 64)
	if !ok {
		return nil, nil
	}
	replay := sha256.Sum256(join(id[:], b[96:128]))
	if _, ok := s.replay[replay]; ok {
		digest := sha256.Sum256(packet)
		for _, p := range s.pending {
			if p.source == source && p.helloHash == digest {
				return append([]byte(nil), p.response...), nil
			}
		}
		return nil, nil
	}
	if len(s.replay) >= 4096 || len(s.pending) >= 256 {
		return nil, nil
	}
	hello := b[:helloSize]
	if !verify(pub, ClientContext, frame(ClientHello, hello), b[helloSize:]) {
		return nil, nil
	}
	if _, exists := s.peerLimits[[32]byte(id)]; !exists && len(s.peerLimits) >= 4096 {
		return nil, nil
	}
	s.peerLimits[[32]byte(id)], ok = allow(s.peerLimits[[32]byte(id)], now, 4)
	if !ok {
		return nil, nil
	}
	kp, err := mlkem1024.Scheme().UnmarshalBinaryPublicKey(hello[200:])
	if err != nil {
		return nil, nil
	}
	ct, ss, err := mlkem1024.Scheme().Encapsulate(kp)
	if err != nil {
		return nil, nil
	}
	defer clear(ss)
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil
	}
	sid := ID(s.Public)
	hash := transcript(hello, sid, s.Keys, nonce, ct)
	psk, hk := derive(ss, hash)
	defer clear(psk[:])
	defer clear(hk[:])
	sig, err := s.Identity.Sign(ctx, ServerContext, hash[:])
	if err != nil {
		clear(psk[:])
		clear(hk[:])
		return nil, nil
	}
	if s.pending == nil {
		s.pending = make(map[[32]byte]*pending)
		s.replay = make(map[[32]byte]time.Time)
	}
	response := frame(ServerHello, join(sid[:], s.Keys.WG[:], s.Keys.Disco[:], nonce, ct, sig, proof(hk, "server-finished", hash)))
	s.pending[hash] = &pending{session: Session{Peer: id, Keys: Keys{[32]byte(b[32:64]), [32]byte(b[64:96])}, PSK: psk}, hash: hash, hk: hk, source: source, expires: now.Add(30 * time.Second), helloHash: sha256.Sum256(packet), response: response}
	s.replay[replay] = now.Add(5 * time.Minute)
	return response, nil
}
