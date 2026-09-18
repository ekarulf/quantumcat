// Package tunnel manages a single OS TUN and explicit IPv6 host routes.
// It never installs default, subnet, or DNS routes.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

type Tunnel struct {
	Device tun.Device
	Name   string
	mu     sync.Mutex
	routes map[netip.Addr]bool
}

func Open() (*Tunnel, error) {
	name := "qcat%d"
	if runtime.GOOS == "darwin" {
		name = "utun"
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, errors.New("TUN mode requires macOS or Linux")
	}
	d, err := tun.CreateTUN(name, 1280)
	if err != nil {
		return nil, fmt.Errorf("create TUN (requires network administration privileges): %w", err)
	}
	actual, err := d.Name()
	if err != nil {
		d.Close()
		return nil, err
	}
	return &Tunnel{Device: d, Name: actual, routes: make(map[netip.Addr]bool)}, nil
}
func command(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, out)
	}
	return nil
}
func (t *Tunnel) Configure(local netip.Addr) error {
	if !local.Is6() || !local.IsPrivate() {
		return errors.New("TUN requires a private IPv6 address")
	}
	if runtime.GOOS == "darwin" {
		return command("/sbin/ifconfig", t.Name, "inet6", local.String(), "prefixlen", "128", "up")
	}
	if err := command("/sbin/ip", "-6", "addr", "add", local.String()+"/128", "dev", t.Name); err != nil {
		return err
	}
	return command("/sbin/ip", "link", "set", "dev", t.Name, "up")
}
func (t *Tunnel) Peer(addr netip.Addr, add bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !addr.Is6() || !addr.IsPrivate() {
		return errors.New("only private IPv6 host routes are supported")
	}
	if t.routes[addr] == add {
		return nil
	}
	verb := "delete"
	if add {
		verb = "add"
	}
	var err error
	if runtime.GOOS == "darwin" {
		err = command("/sbin/route", "-n", verb, "-inet6", addr.String(), "-interface", t.Name)
	} else {
		err = command("/sbin/ip", "-6", "route", verb, addr.String()+"/128", "dev", t.Name)
	}
	if err == nil {
		if add {
			t.routes[addr] = true
		} else {
			delete(t.routes, addr)
		}
	}
	return err
}
func (t *Tunnel) Close() error {
	t.mu.Lock()
	routes := make([]netip.Addr, 0, len(t.routes))
	for addr := range t.routes {
		routes = append(routes, addr)
	}
	t.mu.Unlock()
	var errs []error
	for _, addr := range routes {
		if err := t.Peer(addr, false); err != nil {
			errs = append(errs, err)
		}
	}
	if err := t.Device.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
