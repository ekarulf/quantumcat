package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
)

const (
	DefaultUDPIdleTimeout = 2 * time.Minute
	MaxUDPFlows           = 128
	udpQueueDepth         = 3
	// Restrict to the largest IPv4 UDP payload, also valid over IPv6.
	MaxUDPDatagram = 65507
)

// UDPServices publishes fixed, operator-approved destinations. A packet cannot
// select a destination host or port. The returned handler shares one flow cap
// across all published services and closes flows on process cancellation.
func UDPServices(ctx context.Context, targets map[uint16]string) (func(uint16) func(tailcat.ConnPacketConn), error) {
	configured := make(map[uint16]string, len(targets))
	for port, target := range targets {
		if port == 0 {
			return nil, errors.New("UDP service port must be nonzero")
		}
		if err := ValidateTarget(target); err != nil {
			return nil, err
		}
		configured[port] = target
	}
	slots := make(chan struct{}, MaxUDPFlows)
	return func(port uint16) func(tailcat.ConnPacketConn) {
		target, ok := configured[port]
		if !ok {
			return nil
		}
		return func(in tailcat.ConnPacketConn) {
			defer in.Close()
			select {
			case <-ctx.Done():
				return
			case slots <- struct{}{}:
			default:
				return
			}
			defer func() { <-slots }()
			stopIn := context.AfterFunc(ctx, func() { in.Close() })
			defer stopIn()
			dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			out, err := (&net.Dialer{}).DialContext(dialCtx, "udp", target)
			cancel()
			if err != nil {
				return
			}
			defer out.Close()
			udp, ok := out.(*net.UDPConn)
			if !ok {
				return
			}
			stopOut := context.AfterFunc(ctx, func() { udp.Close() })
			defer stopOut()
			// Tailcat supplies the idle timeout; framing handles larger datagrams.
			proxyUDPDatagrams(FramedUDP(in), udp)
		}
	}, nil
}

// ForwardUDP owns local until return. Each source IP:port is mapped to its own
// connected tunnel socket, so replies cannot cross between local applications.
// Slow flows have a three-datagram queue that drops the oldest pending packet.
// UDP delivery is best effort: there is no acknowledgement or retry layer.
func ForwardUDP(ctx context.Context, local *net.UDPConn, dial func(context.Context) (net.Conn, error), idle time.Duration) error {
	if idle <= 0 {
		return errors.New("UDP idle timeout must be positive")
	}
	if local == nil || dial == nil {
		return errors.New("UDP listener and dialer are required")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { local.Close() })
	var wg sync.WaitGroup
	defer func() { cancel(); stop(); local.Close(); wg.Wait() }()
	type flow struct{ queue chan []byte }
	var mu sync.Mutex
	flows := map[netip.AddrPort]*flow{}
	start := func(source netip.AddrPort, f *flow) {
		defer wg.Done()
		defer func() {
			mu.Lock()
			if flows[source] == f {
				delete(flows, source)
			}
			mu.Unlock()
		}()
		flowCtx, end := context.WithCancel(ctx)
		defer end()
		dialCtx, stopDial := context.WithTimeout(flowCtx, 10*time.Second)
		remote, err := dial(dialCtx)
		stopDial()
		if err != nil {
			return
		}
		defer remote.Close()
		stopRemote := context.AfterFunc(flowCtx, func() { remote.Close() })
		defer stopRemote()
		remote.SetReadDeadline(time.Now().Add(idle))
		readerDone := make(chan struct{})
		go func() {
			defer close(readerDone)
			defer end()
			b := make([]byte, MaxUDPDatagram+1)
			for {
				n, err := remote.Read(b)
				if err != nil {
					return
				}
				if n > MaxUDPDatagram {
					continue
				}
				remote.SetReadDeadline(time.Now().Add(idle))
				if _, err = local.WriteToUDPAddrPort(b[:n], source); err != nil {
					return
				}
			}
		}()
		defer func() { end(); remote.Close(); <-readerDone }()
		for {
			select {
			case <-flowCtx.Done():
				return
			case packet := <-f.queue:
				remote.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if n, err := remote.Write(packet); err != nil || n != len(packet) {
					return
				}
				remote.SetReadDeadline(time.Now().Add(idle))
			}
		}
	}
	buffer := make([]byte, MaxUDPDatagram+1)
	for {
		n, source, err := local.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("UDP listener: %w", err)
		}
		if n > MaxUDPDatagram {
			continue
		}
		mu.Lock()
		f := flows[source]
		if f == nil {
			if len(flows) >= MaxUDPFlows {
				mu.Unlock()
				continue
			}
			f = &flow{queue: make(chan []byte, udpQueueDepth)}
			flows[source] = f
			wg.Add(1)
			go start(source, f)
		}
		packet := append([]byte{}, buffer[:n]...)
		select {
		case f.queue <- packet:
		default:
			select {
			case <-f.queue:
			default:
			}
			select {
			case f.queue <- packet:
			default:
			}
		}
		mu.Unlock()
	}
}
