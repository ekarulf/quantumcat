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

// State is the private ratchet state for one client WireGuard identity. It is
// never serialized or sent on the wire. The zero value represents the initial
// bootstrap; every committed handshake produces a valid state with its own
// root secret, transcript hash, and epoch.
type State struct {
	Epoch      uint64
	Transcript [hashSize]byte
	Root       [hashSize]byte
	valid      bool
}

func (s State) nextEpoch() uint64 {
	if !s.valid {
		return 0
	}
	return s.Epoch + 1
}

// derive advances the sparse PQ ratchet. The HMAC is HKDF-Extract with the
// previous root as salt. Fresh ML-KEM entropy is always injected; the parent
// and new transcript hashes plus epoch bind that entropy to this exact edge of
// the ratchet rather than merely to a fresh but interchangeable handshake.
func derive(parent State, ss []byte, hash [hashSize]byte) (next State, psk, confirmation [32]byte, err error) {
	epoch := parent.nextEpoch()
	m := hmac.New(sha512.New384, parent.Root[:])
	m.Write([]byte(rootDomain))
	m.Write(ss)
	m.Write(parent.Transcript[:])
	m.Write(hash[:])
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], epoch)
	m.Write(sequence[:])
	copy(next.Root[:], m.Sum(nil))
	clear(sequence[:])
	next.Epoch, next.Transcript, next.valid = epoch, hash, true
	p, err := hkdf.Expand(sha512.New384, next.Root[:], "qcat-wireguard-psk-v3"+string(hash[:]), 32)
	if err != nil {
		clear(next.Root[:])
		return State{}, psk, confirmation, err
	}
	defer clear(p)
	c, err := hkdf.Expand(sha512.New384, next.Root[:], "qcat-handshake-confirm-v3"+string(hash[:]), 32)
	if err != nil {
		clear(next.Root[:])
		return State{}, psk, confirmation, err
	}
	defer clear(c)
	copy(psk[:], p)
	copy(confirmation[:], c)
	return next, psk, confirmation, nil
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
	parent       State
	next         State
	accepted     bool
}

func NewClient(ctx context.Context, identity provider.Identity, newKEM provider.NewKEM, serverPublic []byte, local, remote Keys, now time.Time) (*Client, []byte, error) {
	return NewClientWithState(ctx, identity, newKEM, serverPublic, local, remote, State{}, now)
}

// NewClientWithState starts either the initial bootstrap (zero state) or the
// next authenticated ratchet step. Callers must retain State only after
// Accepted succeeds; speculative ServerHello processing must not advance the
// caller's committed state.
func NewClientWithState(ctx context.Context, identity provider.Identity, newKEM provider.NewKEM, serverPublic []byte, local, remote Keys, parent State, now time.Time) (*Client, []byte, error) {
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
	parentEpoch := make([]byte, 8)
	binary.BigEndian.PutUint64(parentEpoch, parent.nextEpoch())
	hello := join(tag[:], local.WG[:], local.Disco[:], nonce, sid[:], parent.Transcript[:], parentEpoch, stamp, kp)
	clear(parentEpoch)
	sig, err := identity.Sign(ctx, ClientContext, frame(ClientHello, hello))
	if err != nil {
		return fail(err)
	}
	c := &Client{identity: identity, kem: kem, hello: hello, server: sid, serverPublic: append([]byte(nil), serverPublic...), keys: remote, parent: parent}
	return c, frame(ClientHello, join(hello, sig)), nil
}
func (c *Client) Close() {
	c.kem.Destroy()
	clear(c.parent.Root[:])
	clear(c.next.Root[:])
}
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
	next, psk, hk, err := derive(c.parent, ss, hash)
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
	c.next = next
	c.ack = frame(ServerAccepted, join(hash[:], proof(hk, "server-accepted", hash)))
	return psk, frame(ClientFinish, join(hash[:], proof(hk, "client-finished", hash))), nil
}
func (c *Client) Accepted(packet []byte) bool {
	c.accepted = len(c.ack) > 0 && hmac.Equal(c.ack, packet)
	return c.accepted
}

// State returns the candidate state only after the server's authenticated
// acknowledgement was accepted. A zero result means this Client has not
// completed and committed a handshake.
func (c *Client) State() State {
	if !c.accepted {
		return State{}
	}
	return c.next
}

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
	state      State
	hash       [hashSize]byte
	hk         [32]byte
	source     [32]byte
	expires    time.Time
	accepted   bool
	installing bool
	helloHash  [hashSize]byte
	response   []byte
}
type committed struct {
	peer  PeerID
	keys  Keys
	state State
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
	committed  map[[32]byte]committed
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
			clear(p.state.Root[:])
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
		clear(p.state.Root[:])
		delete(s.pending, h)
	}
	for source, state := range s.committed {
		clear(state.state.Root[:])
		delete(s.committed, source)
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

// parent returns the one ratchet state that may advance for this transport
// identity. A previously unseen node can only bootstrap epoch zero with an all
// zero parent hash. Once installed, every renewal must name the last committed
// transcript and the immediately following epoch. The comparison happens only
// after ML-DSA authentication, so unauthenticated packets cannot probe state.
func (s *Server) parent(source [32]byte, peer PeerID, keys Keys, epoch uint64, previous [hashSize]byte) (State, bool) {
	current, ok := s.committed[source]
	if !ok {
		return State{}, epoch == 0 && previous == [hashSize]byte{}
	}
	if current.peer != peer || current.keys != keys || !current.state.valid || current.state.Epoch == ^uint64(0) {
		return State{}, false
	}
	return current.state, epoch == current.state.Epoch+1 && hmac.Equal(previous[:], current.state.Transcript[:])
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
			clear(p.state.Root[:])
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
				clear(other.state.Root[:])
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
					if s.committed == nil {
						s.committed = make(map[[32]byte]committed)
					}
					old, replaced := s.committed[p.source]
					if replaced {
						clear(old.state.Root[:])
					}
					s.committed[p.source] = committed{peer: p.session.Peer, keys: p.session.Keys, state: p.state}
					clear(p.state.Root[:])
					// Keep only the confirmation key long enough for a client that
					// lost ServerAccepted to resume its exact ClientFinish retry.
					p.expires = time.Now().Add(5 * time.Minute)
				} else {
					clear(p.hk[:])
					clear(p.state.Root[:])
					delete(s.pending, h)
				}
			})
		}
		return ack, &session
	}
	if kind != ClientHello {
		return nil, nil
	}
	if source != [32]byte(b[clientWGOffset:clientWGOffset+32]) || [32]byte(b[clientDiscoOffset:clientDiscoOffset+32]) == [32]byte{} || PeerID(b[serverIDOffset:serverIDOffset+32]) != ID(s.Public) {
		return nil, nil
	}
	stamp := int64(binary.BigEndian.Uint64(b[timestampOffset : timestampOffset+8]))
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
	id, pub := s.resolve(b[peerTagOffset:peerTagOffset+32], b[nonceOffset:nonceOffset+32])
	if len(pub) == 0 || ID(pub) != id {
		return nil, nil
	}
	s.global, ok = allow(s.global, now, 64)
	if !ok {
		return nil, nil
	}
	replay := sha512.Sum384(join(id[:], b[nonceOffset:nonceOffset+32]))
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
	keys := Keys{WG: [32]byte(b[clientWGOffset : clientWGOffset+32]), Disco: [32]byte(b[clientDiscoOffset : clientDiscoOffset+32])}
	previous := [hashSize]byte(b[parentHashOffset : parentHashOffset+hashSize])
	epoch := binary.BigEndian.Uint64(b[epochOffset : epochOffset+8])
	parent, ok := s.parent(source, id, keys, epoch, previous)
	if !ok {
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
	kp, err := mlkem.NewEncapsulationKey1024(hello[kemOffset:])
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
	next, psk, hk, err := derive(parent, ss, hash)
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
	}
	if s.replay == nil {
		s.replay = make(map[[hashSize]byte]time.Time)
	}
	if s.committed == nil {
		s.committed = make(map[[32]byte]committed)
	}
	response := frame(ServerHello, join(sid[:], s.Keys.WG[:], s.Keys.Disco[:], nonce, ct, sig, proof(hk, "server-finished", hash)))
	s.pending[hash] = &pending{session: Session{Peer: id, Keys: keys, PSK: psk}, state: next, hash: hash, hk: hk, source: source, expires: now.Add(30 * time.Second), helloHash: sha512.Sum384(packet), response: response}
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
