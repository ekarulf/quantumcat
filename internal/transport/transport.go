package transport

import (
	"bytes"
	"context"
	"errors"
	"iter"
	"sync"
	"time"

	"github.com/ekarulf/quantumcat/internal/crypto/provider"
	"github.com/ekarulf/quantumcat/internal/protocol"
	"github.com/tailscale/tailcat"
	"go4.org/mem"
	"tailscale.com/types/key"
)

const (
	SessionLifetime = time.Hour
	RenewInterval   = 45 * time.Minute
)

func Keys(node key.NodePrivate) protocol.Keys {
	wg := node.Public().Raw32()
	disco := tailcat.DiscoPublicForNode(node).Raw32()
	return protocol.Keys{WG: wg, Disco: disco}
}
func Server(identity provider.Identity, pub []byte, node key.NodePrivate, authorized iter.Seq2[protocol.PeerID, []byte]) *tailcat.Server {
	return serverWithLifetime(identity, pub, node, authorized, SessionLifetime)
}

func serverWithLifetime(identity provider.Identity, pub []byte, node key.NodePrivate, authorized iter.Seq2[protocol.PeerID, []byte], lifetime time.Duration) *tailcat.Server {
	p := &protocol.Server{Identity: identity, Public: pub, Keys: Keys(node), Authorized: authorized}
	return &tailcat.Server{
		BootstrapCleanup:    func() { p.Expire(time.Now()) },
		BootstrapClose:      p.Close,
		ValidBootstrapFrame: protocol.ValidFrame,
		Key:                 node, DisablePresharedKey: true,
		Bootstrap: func(src key.NodePublic, b []byte) ([]byte, *tailcat.AuthenticatedPeer) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			reply, session := p.Handle(ctx, src.Raw32(), b, time.Now())
			if session == nil {
				return reply, nil
			}
			peer := &tailcat.AuthenticatedPeer{Identity: [32]byte(session.Peer), Disco: key.DiscoPublicFromRaw32(mem.B(session.Keys.Disco[:])), PSK: tailcat.PresharedKey(session.PSK), Installed: session.Installed}
			id := session.Peer
			pinned := append([]byte(nil), protocol.Lookup(authorized, id)...)
			expires := time.Now().Add(lifetime)
			peer.Valid = func() bool {
				return time.Now().Before(expires) && len(pinned) > 0 && bytes.Equal(protocol.Lookup(authorized, id), pinned)
			}
			clear(session.PSK[:])
			return reply, peer
		},
	}
}
func Client(identity provider.Identity, newKEM provider.NewKEM, pub []byte, endpoint tailcat.Addr) (*tailcat.Client, error) {
	ci, err := tailcat.ParseAddr(endpoint)
	if err != nil {
		return nil, err
	}
	if !ci.PresharedKey.IsZero() {
		return nil, errors.New("endpoint contains a bearer PSK")
	}
	node := key.NewNode()
	c := tailcat.NewClient(endpoint)
	c.Key = node
	// State advances only after ServerAccepted. Retaining a finished handshake
	// across a caller timeout lets a later Renew retry its exact ClientFinish
	// instead of accidentally proposing an old parent after the server has
	// already committed the new ratchet state.
	var state protocol.State
	var pending *protocol.Client
	var pendingPacket []byte
	var pendingPSK [32]byte
	var stateMu sync.Mutex
	c.Bootstrap = func(ctx context.Context, send func([]byte) error, recv <-chan []byte) (tailcat.PresharedKey, error) {
		ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		remote := protocol.Keys{WG: ci.ServerPublic.Raw32(), Disco: ci.ServerDiscoPublic.Raw32()}
		stateMu.Lock()
		handshake := pending
		packet := append([]byte(nil), pendingPacket...)
		psk := pendingPSK
		stateMu.Unlock()
		finishing := handshake != nil
		if !finishing {
			var hello []byte
			var err error
			stateMu.Lock()
			parent := state
			stateMu.Unlock()
			handshake, hello, err = protocol.NewClientWithState(ctx, identity, newKEM, pub, Keys(node), remote, parent, time.Now())
			if err != nil {
				return tailcat.PresharedKey{}, err
			}
			packet = hello
		}
		// A fresh attempt that never reaches ClientFinish owns an ephemeral KEM
		// key. A completed attempt is retained so a later caller can retry its
		// authenticated finish without losing ratchet synchronization.
		defer func() {
			if !finishing {
				handshake.Close()
			}
		}()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		defer clear(psk[:])
		if err := send(packet); err != nil {
			return tailcat.PresharedKey{}, err
		}
		for {
			select {
			case <-ctx.Done():
				return tailcat.PresharedKey{}, ctx.Err()
			case <-ticker.C:
				if err := send(packet); err != nil {
					return tailcat.PresharedKey{}, err
				}
			case reply := <-recv:
				if finishing {
					if handshake.Accepted(reply) {
						stateMu.Lock()
						state = handshake.State()
						if pending == handshake {
							pending, pendingPacket = nil, nil
							clear(pendingPSK[:])
						}
						stateMu.Unlock()
						handshake.Close()
						return tailcat.PresharedKey(psk), nil
					}
					continue
				}
				var finish []byte
				var err error
				psk, finish, err = handshake.Complete(ctx, reply)
				if err != nil {
					continue
				}
				packet = finish
				finishing = true
				stateMu.Lock()
				pending, pendingPacket, pendingPSK = handshake, append([]byte(nil), finish...), psk
				stateMu.Unlock()
				if err := send(packet); err != nil {
					return tailcat.PresharedKey{}, err
				}
			}
		}
	}
	return c, nil
}
