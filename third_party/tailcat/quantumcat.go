package tailcat

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// RefreshNetwork discards stale outer network paths, not application sockets or
// WireGuard identity. Rebind also checks existing DERP connections for liveness.
func (c *Client) RefreshNetwork() error {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()
	c.startMu.Lock()
	defer c.startMu.Unlock()
	if c.closed || c.lb == nil {
		return errors.New("authenticated client is not running")
	}
	mc := c.lb.sys.MagicSock.Get()
	mc.Rebind()
	mc.ReSTUN("qcat-recovery")
	return nil
}

// Probe checks the encrypted data path, not just the relay/discovery path (which
// can work even after the server has expired our authenticated lease).
func (c *Client) Probe(ctx context.Context) error {
	// TSMP, like UDP, is not retransmitted by WireGuard. A packet sent with an
	// old traffic key while a replacement handshake is starting may be lost.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	ch := make(chan error, 1)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.startMu.Lock()
		if c.closed || c.lb == nil {
			c.startMu.Unlock()
			return errors.New("authenticated client is not running")
		}
		c.lb.sys.Engine.Get().Ping(tcAddrForKey(c.lb.serverPub), tailcfg.PingTSMP, 0, func(r *ipnstate.PingResult) {
			var err error
			if r.Err != "" {
				err = errors.New(r.Err)
			}
			select {
			case ch <- err:
			default:
			}
		})
		c.startMu.Unlock()
		select {
		case err := <-ch:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Client) Status() *ipnstate.Status {
	c.startMu.Lock()
	defer c.startMu.Unlock()
	if c.lb == nil {
		return nil
	}
	return c.lb.Status()
}

// NodeAddress returns the host address in Quantumcat's private ULA prefix.
func NodeAddress(k key.NodePublic) netip.Addr { return tcAddrForKey(k) }

// AuthenticatedPeer is returned only after the caller verifies mutual key confirmation.
type AuthenticatedPeer struct {
	// Identity binds renewals of an existing node to the original PQ identity.
	Identity  [32]byte
	Disco     key.DiscoPublic
	PSK       PresharedKey
	Valid     func() bool
	Installed func(bool)
	Removed   func()
}

// Renew repeats authentication without recreating the device, netstack, node
// address, or sockets. Existing WireGuard traffic keys survive the PSK update.
func (c *Client) Renew(ctx context.Context) error {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()
	c.startMu.Lock()
	if c.closed || !c.started || c.lb == nil || c.Bootstrap == nil {
		c.startMu.Unlock()
		return errors.New("authenticated client is not running")
	}
	// Close also holds renewMu, so this backend remains live through renewal.
	lb := c.lb
	c.startMu.Unlock()
	send := func(pkt []byte) error {
		_, err := lb.sys.MagicSock.Get().SendDERPPacketTo(lb.serverPub, lb.derpRegionID(), pkt)
		return err
	}
	psk, err := c.Bootstrap(ctx, send, c.bootstrapInbox)
	if err != nil {
		return err
	}
	defer clear(psk[:])
	if psk.IsZero() {
		return errors.New("renewal returned zero PSK")
	}
	lb.mu.Lock()
	lb.presharedKey = psk
	lb.mu.Unlock()
	lb.sys.Engine.Get().SyncDevicePeer(lb.serverPub)
	lb.sys.Engine.Get().MarkDevicePeerForHandshake(lb.serverPub)
	return nil
}
