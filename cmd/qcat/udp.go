package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ekarulf/quantumcat/internal/proxy"
	"github.com/tailscale/tailcat"
)

// UDP's destination is a published tunnel port, not a client-selected host.
func udpForwardSpec(spec string) (local string, remote uint16, err error) {
	l, r, ok := strings.Cut(spec, ":")
	if !ok {
		return "", 0, errors.New("UDP forward requires LOCALPORT:TUNNELPORT")
	}
	lp, e := strconv.ParseUint(l, 10, 16)
	if e != nil {
		return "", 0, fmt.Errorf("invalid local UDP port %q", l)
	}
	rp, e := strconv.ParseUint(r, 10, 16)
	if e != nil || rp == 0 {
		return "", 0, fmt.Errorf("invalid tunnel UDP port %q", r)
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(lp))), uint16(rp), nil
}

func udpServiceSpecs(entries []string) (map[uint16]string, error) {
	targets := map[uint16]string{}
	for _, entry := range entries {
		p, target, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, errors.New("--udp requires PORT=HOST:PORT")
		}
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil || port == 0 {
			return nil, errors.New("UDP service port must be 1–65535")
		}
		if err = proxy.ValidateTarget(target); err != nil {
			return nil, err
		}
		if _, exists := targets[uint16(port)]; exists {
			return nil, fmt.Errorf("duplicate UDP service port %d", port)
		}
		targets[uint16(port)] = target
	}
	return targets, nil
}

func forwardUDP(ctx context.Context, c *tailcat.Client, listen string, port uint16, idle time.Duration) error {
	addr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		return err
	}
	local, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	defer local.Close()
	fmt.Fprintf(os.Stderr, "Listening on UDP %s -> tunnel port %d\n", local.LocalAddr(), port)
	return proxy.ForwardUDP(ctx, local, func(ctx context.Context) (net.Conn, error) {
		conn, err := c.DialUDPPort(ctx, port)
		if err != nil {
			return nil, err
		}
		return proxy.FramedUDP(conn), nil
	}, idle)
}
