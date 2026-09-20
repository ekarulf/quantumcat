package transport

import (
	"bytes"
	"context"
	"errors"
	"iter"
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
	c.Bootstrap = func(ctx context.Context, send func([]byte) error, recv <-chan []byte) (tailcat.PresharedKey, error) {
		ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		remote := protocol.Keys{WG: ci.ServerPublic.Raw32(), Disco: ci.ServerDiscoPublic.Raw32()}
		handshake, hello, err := protocol.NewClient(ctx, identity, newKEM, pub, Keys(node), remote, time.Now())
		if err != nil {
			return tailcat.PresharedKey{}, err
		}
		defer handshake.Close()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		packet := hello
		var psk [32]byte
		defer clear(psk[:])
		finishing := false
		if err = send(packet); err != nil {
			return tailcat.PresharedKey{}, err
		}
		for {
			select {
			case <-ctx.Done():
				return tailcat.PresharedKey{}, ctx.Err()
			case <-ticker.C:
				if err = send(packet); err != nil {
					return tailcat.PresharedKey{}, err
				}
			case reply := <-recv:
				if finishing {
					if handshake.Accepted(reply) {
						return tailcat.PresharedKey(psk), nil
					}
					continue
				}
				var finish []byte
				psk, finish, err = handshake.Complete(ctx, reply)
				if err != nil {
					continue
				}
				packet = finish
				finishing = true
				if err = send(packet); err != nil {
					return tailcat.PresharedKey{}, err
				}
			}
		}
	}
	return c, nil
}
