package tailcat

import (
	"net/netip"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

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
	Disco key.DiscoPublic
	PSK   PresharedKey
	Valid func() bool
}
