package main

import (
	"fmt"
	"io"

	"github.com/ekarulf/quantumcat/internal/config"
	"github.com/ekarulf/quantumcat/internal/protocol"
	"tailscale.com/wgengine/filter"
)

func publishedTCPPorts(targets map[uint16]string) []filter.PortRange {
	ports := []filter.PortRange{{First: 1, Last: 1}}
	for port := range targets {
		ports = append(ports, filter.PortRange{First: port, Last: port})
	}
	return ports
}

type authorizationReload struct {
	error    string
	failures int
}

func reloadAuthorizations(s config.Store, log io.Writer, state *authorizationReload, current map[protocol.PeerID][]byte) map[protocol.PeerID][]byte {
	next := map[protocol.PeerID][]byte{}
	peers, err := s.Peers()
	if err != nil {
		state.failures++
		message := err.Error()
		if message != state.error || state.failures == 3 {
			if state.failures < 3 {
				fmt.Fprintf(log, "qcat: peer reload failed (%d/3); keeping last-known-good authorizations: %v\n", state.failures, err)
			} else {
				fmt.Fprintf(log, "qcat: peer reload failed 3 times; revoking %d authorizations: %v\n", len(current), err)
			}
			state.error = message
		}
		if state.failures < 3 {
			return current
		}
		return next
	}
	if state.failures != 0 {
		fmt.Fprintln(log, "qcat: peer configuration valid again; restoring configured authorizations")
		*state = authorizationReload{}
	}
	for _, peer := range peers {
		next[protocol.ID(peer.PublicKey)] = peer.PublicKey
	}
	return next
}
