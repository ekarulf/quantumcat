package main

import (
	"fmt"
	"github.com/ekarulf/quantumcat/internal/config"
	"github.com/ekarulf/quantumcat/internal/protocol"
	"io"
	"tailscale.com/wgengine/filter"
)

func publishedTCPPorts(targets map[uint16]string) []filter.PortRange {
	ports := []filter.PortRange{{First: 1, Last: 1}}
	for port := range targets {
		ports = append(ports, filter.PortRange{First: port, Last: port})
	}
	return ports
}

func reloadAuthorizations(s config.Store, log io.Writer, previous *string) map[protocol.PeerID][]byte {
	next := map[protocol.PeerID][]byte{}
	peers, err := s.Peers()
	if err != nil {
		if message := err.Error(); message != *previous {
			fmt.Fprintf(log, "qcat: peer reload failed; revoking all authorizations: %v\n", err)
			*previous = message
		}
		return next
	}
	if *previous != "" {
		fmt.Fprintln(log, "qcat: peer configuration valid again; restoring configured authorizations")
		*previous = ""
	}
	for _, peer := range peers {
		next[protocol.ID(peer.PublicKey)] = peer.PublicKey
	}
	return next
}
