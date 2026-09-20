package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ekarulf/quantumcat/internal/crypto/provider/software"
	"github.com/ekarulf/quantumcat/internal/protocol"
	"github.com/tailscale/tailcat"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/nettype"
	"tailscale.com/wgengine/filter"
)

func TestWatchRecoversAfterSleepAndFailedProbe(t *testing.T) {
	for _, sleep := range []bool{true, false} {
		t.Run(fmt.Sprint("sleep=", sleep), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ticks := make(chan time.Time, 20)
			for i := 0; i < cap(ticks); i++ {
				ticks <- time.Time{} // Deliberately stale: watch must read now().
			}
			clock := time.Unix(100, 0)
			reads, probes, refreshes, attempts := 0, 0, 0, 0
			watch(ctx, func(context.Context) error {
				attempts++
				if attempts == 1 {
					return errors.New("network still offline")
				}
				cancel()
				return nil
			}, func(context.Context) error {
				probes++
				return errors.New("blackholed data path")
			}, func() error { refreshes++; return nil }, time.Hour, time.Second, ticks, func() time.Time {
				reads++
				if sleep && reads == 2 {
					clock = clock.Add(2 * time.Hour)
				} else {
					clock = clock.Add(5 * time.Second)
				}
				return clock
			}, nil)
			if attempts != 2 || refreshes != 2 || (!sleep && probes == 0) {
				t.Fatalf("attempts=%d refreshes=%d probes=%d", attempts, refreshes, probes)
			}
		})
	}
}

func TestRenewalRetriesWithoutExiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts, failures := 0, 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		maintain(ctx, func(context.Context) error {
			attempts++
			if attempts == 1 {
				return errors.New("temporary loss")
			}
			if attempts == 3 {
				cancel()
			}
			return nil
		}, 10*time.Millisecond, time.Millisecond, func(error) { failures++ })
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("renewal did not retry/shut down")
	}
	if attempts != 3 || failures != 1 {
		t.Fatalf("attempts=%d failures=%d", attempts, failures)
	}
}

func TestTCPStreamSurvivesRenewalAndLostAcknowledgement(t *testing.T) {
	// Allow real DERP/WireGuard retries on hosted race-test runners. The lease
	// must exceed bootstrap + rebind + the first renewal, or this tests accidental
	// expiry during setup rather than preservation of a renewed TCP stream.
	const lease = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	relay := derpserver.New(key.NewNode(), t.Logf)
	httpRelay := httptest.NewTLSServer(derpserver.Handler(relay))
	t.Cleanup(func() { relay.Close(); httpRelay.Close() })
	stun, closeSTUN := stuntest.ServeWithPacketListener(t, nettype.Std{})
	defer closeSTUN()
	si, _ := software.Generate()
	ci, _ := software.Generate()
	sp, _ := si.PublicKey(ctx)
	cp, _ := ci.PublicKey(ctx)
	var revoked, wrongOwner atomic.Bool
	server := serverWithLifetime(si, sp, key.NewNode(), func(yield func(protocol.PeerID, []byte) bool) {
		if !revoked.Load() {
			yield(protocol.ID(cp), cp)
		}
	}, lease)
	server.Region = &tailcfg.DERPRegion{RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{
		Name: "test", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none",
		DERPPort: httpRelay.Listener.Addr().(*net.TCPAddr).Port, STUNPort: stun.Port, STUNTestIP: "127.0.0.1", InsecureForTests: true,
	}}}
	server.OnTCP = func(port uint16) func(net.Conn) {
		if port != 2222 {
			return nil
		}
		return func(c net.Conn) { defer c.Close(); io.Copy(c, c) }
	}
	server.ServedUDPPorts = []filter.PortRange{{First: 60001, Last: 60001}}
	server.OnUDP = func(port uint16) func(tailcat.ConnPacketConn) {
		if port != 60001 {
			return nil
		}
		return func(c tailcat.ConnPacketConn) {
			defer c.Close()
			var b [128]byte
			for {
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := c.Read(b[:])
				if err != nil {
					return
				}
				if _, err = c.Write(b[:n]); err != nil {
					return
				}
			}
		}
	}
	var routeAdds, commits atomic.Int32
	server.OnTunnelPeer = func(_ key.NodePublic, add bool) error {
		if add {
			routeAdds.Add(1)
		}
		return nil
	}
	var droppedAck, freshPSK atomic.Bool
	var previous tailcat.PresharedKey // Accessed only by serialized bootstrap worker.
	original := server.Bootstrap
	server.Bootstrap = func(src key.NodePublic, packet []byte) ([]byte, *tailcat.AuthenticatedPeer) {
		reply, peer := original(src, packet)
		if peer != nil {
			if wrongOwner.Load() {
				peer.Identity[0] ^= 1
			}
			if !previous.IsZero() && previous != peer.PSK {
				freshPSK.Store(true)
			}
			previous = peer.PSK
			installed := peer.Installed
			peer.Installed = func(ok bool) {
				installed(ok)
				if ok {
					commits.Add(1)
				}
			}
			// Lose the first renewal's ACK after the server has installed its PSK.
			if commits.Load() > 0 && droppedAck.CompareAndSwap(false, true) {
				reply = nil
			}
		}
		return reply, peer
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	c, err := Client(ci, software.NewKEM, sp, server.TailcatAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialTCPPort(ctx, 2222)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	node, addr := c.PublicKey(), conn.LocalAddr().String()
	exchange := func(value uint32) {
		t.Helper()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		var sent, received [4]byte
		binary.BigEndian.PutUint32(sent[:], value)
		if _, err := conn.Write(sent[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, received[:]); err != nil {
			t.Fatalf("TCP exchange %d: %v (commits=%d, ackLoss=%v, serverPeers=%d)", value, err, commits.Load(), droppedAck.Load(), len(server.Status().Peer))
		}
		if received != sent {
			t.Fatal("TCP stream corrupted during renewal")
		}
	}
	exchange(0)
	udp, err := c.DialUDPPort(ctx, 60001)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpExchange := func() {
		t.Helper()
		udp.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := udp.Write([]byte("wake")); err != nil {
			t.Fatal(err)
		}
		var b [128]byte
		n, err := udp.Read(b[:])
		if err != nil || string(b[:n]) != "wake" {
			t.Fatalf("UDP echo: %q %v", b[:n], err)
		}
	}
	udpExchange()
	if err := c.RefreshNetwork(); err != nil {
		t.Fatal(err)
	}
	probeCtx, stopProbe := context.WithTimeout(ctx, 10*time.Second)
	if err := c.Probe(probeCtx); err != nil {
		t.Fatal(err)
	}
	stopProbe()
	exchange(1) // Outer socket rebind must not replace the TCP stack.
	initialHandshake := time.Time{}
	for _, peer := range c.Status().Peer {
		initialHandshake = peer.LastHandshake
	}
	if initialHandshake.IsZero() {
		t.Fatal("initial WireGuard handshake not recorded")
	}
	renewCtx, stopRenewal := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); maintain(renewCtx, c.Renew, 3*time.Second, 200*time.Millisecond, nil) }()
	defer func() { stopRenewal(); <-done }()
	until := time.Now().Add(lease + 4*time.Second) // Beyond the original server lease.
	for sequence := uint32(1); time.Now().Before(until); sequence++ {
		exchange(sequence)
		time.Sleep(50 * time.Millisecond)
	}
	stopRenewal()
	<-done
	if commits.Load() < 3 || !droppedAck.Load() || !freshPSK.Load() {
		t.Fatalf("renewal scenarios missing: commits=%d ackLoss=%v freshPSK=%v", commits.Load(), droppedAck.Load(), freshPSK.Load())
	}
	if routeAdds.Load() != 1 || c.PublicKey() != node || conn.LocalAddr().String() != addr {
		t.Fatal("renewal recreated transport identity or route")
	}
	newHandshake := false
	for _, peer := range c.Status().Peer {
		newHandshake = peer.LastHandshake.After(initialHandshake)
	}
	if !newHandshake {
		t.Fatal("renewed PSK never completed a fresh WireGuard handshake")
	}

	// An existing node cannot be taken over by a different authenticated identity.
	wrongOwner.Store(true)
	rejectCtx, stopReject := context.WithTimeout(ctx, 3*time.Second)
	if err := c.Renew(rejectCtx); err == nil {
		t.Fatal("accepted renewal for different identity")
	}
	stopReject()
	wrongOwner.Store(false)
	exchange(9999) // Failed renewal must preserve the old live stream.
	// Simulate sleeping beyond the server lease and UDP flow idle timeout.
	// Recovery must work with the existing client and connected UDP socket.
	expiryDeadline := time.Now().Add(lease + 2*time.Second)
	for len(server.Status().Peer) != 0 && time.Now().Before(expiryDeadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(server.Status().Peer) != 0 {
		t.Fatal("lease did not expire")
	}
	if err := c.RefreshNetwork(); err != nil {
		t.Fatal(err)
	}
	if err := c.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	probeCtx, stopProbe = context.WithTimeout(ctx, 10*time.Second)
	if err := c.Probe(probeCtx); err != nil {
		t.Fatal(err)
	}
	stopProbe()
	udpExchange()
	revoked.Store(true)
	revokeCtx, stopRevoke := context.WithTimeout(ctx, time.Second)
	if err := c.Renew(revokeCtx); err == nil {
		t.Fatal("revoked identity renewed")
	}
	stopRevoke()
	deadline := time.Now().Add(3 * time.Second)
	for len(server.Status().Peer) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(server.Status().Peer) != 0 {
		t.Fatal("renewal bypassed revocation")
	}
}

func TestRenewalCancellationInterruptsInFlightAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		maintain(ctx, func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}, time.Millisecond, time.Millisecond, nil)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("renewal not started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("renewal blocked shutdown")
	}
}
