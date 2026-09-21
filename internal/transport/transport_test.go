package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ekarulf/quantumcat/internal/crypto/provider/software"
	"github.com/ekarulf/quantumcat/internal/protocol"
	"github.com/tailscale/tailcat"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/derp/derpserver"
	"tailscale.com/envknob"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/nettype"
)

func TestMain(m *testing.M) {
	envknob.Setenv("IN_TS_TEST", "true")
	netcheck.HookStartCaptivePortalDetection.SetForTest(func(context.Context, *netcheck.Client, *tailcfg.DERPMap, tailcfg.DERPRegionID, func(bool)) (<-chan struct{}, func()) {
		return syncs.ClosedChan(), func() {}
	})
	os.Exit(m.Run())
}

func TestInstallationFailureNeverAcknowledged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
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
	server := Server(si, sp, key.NewNode(), func(yield func(protocol.PeerID, []byte) bool) { yield(protocol.ID(cp), cp) })
	server.Region = &tailcfg.DERPRegion{RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{
		Name: "test", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none",
		DERPPort: httpRelay.Listener.Addr().(*net.TCPAddr).Port, STUNPort: stun.Port, STUNTestIP: "127.0.0.1", InsecureForTests: true,
	}}}
	var installs, finishes atomic.Int32
	server.OnTunnelPeer = func(key.NodePublic, bool) error {
		installs.Add(1)
		return errors.New("simulated route installation failure")
	}
	original := server.Bootstrap
	server.Bootstrap = func(src key.NodePublic, packet []byte) ([]byte, *tailcat.AuthenticatedPeer) {
		kind, _, _ := protocol.Parse(packet)
		if kind == protocol.ClientFinish {
			finishes.Add(1)
		}
		return original(src, packet)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := Client(ci, software.NewKEM, sp, server.TailcatAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Ping(ctx); err == nil {
		t.Fatal("acknowledged failed installation")
	}
	if installs.Load() != 1 || finishes.Load() < 2 {
		t.Fatalf("failure/retry path not exercised: installs=%d finishes=%d", installs.Load(), finishes.Load())
	}
	if len(server.Status().Peer) != 0 {
		t.Fatal("failed installation retained peer state")
	}
}
func TestTunnelAuthenticationLossAndRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	relay := derpserver.New(key.NewNode(), t.Logf)
	httpRelay := httptest.NewTLSServer(derpserver.Handler(relay))
	t.Cleanup(func() { relay.Close(); httpRelay.Close() })
	stun, closeSTUN := stuntest.ServeWithPacketListener(t, nettype.Std{})
	defer closeSTUN()
	region := &tailcfg.DERPRegion{RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{
		Name: "test1", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none",
		DERPPort: httpRelay.Listener.Addr().(*net.TCPAddr).Port, STUNPort: stun.Port, STUNTestIP: "127.0.0.1", InsecureForTests: true,
	}}}
	si, _ := software.Generate()
	ci, _ := software.Generate()
	sp, _ := si.PublicKey(ctx)
	cp, _ := ci.PublicKey(ctx)
	var revoked atomic.Bool
	server := Server(si, sp, key.NewNode(), func(yield func(protocol.PeerID, []byte) bool) {
		if !revoked.Load() {
			yield(protocol.ID(cp), cp)
		}
	})
	server.Region = region
	server.Logf = t.Logf
	server.OnTCP = func(p uint16) func(net.Conn) {
		if p != 2222 {
			return nil
		}
		return func(c net.Conn) { defer c.Close(); io.Copy(c, c) }
	}
	original := server.Bootstrap
	var droppedHello, droppedAck atomic.Bool
	server.Bootstrap = func(src key.NodePublic, p []byte) ([]byte, *tailcat.AuthenticatedPeer) {
		reply, session := original(src, p)
		kind, _, _ := protocol.Parse(reply)
		if kind == protocol.ServerHello && droppedHello.CompareAndSwap(false, true) {
			reply = nil
		}
		if kind == protocol.ServerAccepted && droppedAck.CompareAndSwap(false, true) {
			reply = nil
		}
		return reply, session
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ciAddr, err := tailcat.ParseAddr(server.TailcatAddr())
	if err != nil || !ciAddr.PresharedKey.IsZero() {
		t.Fatal("descriptor exposes PSK")
	}
	client, err := Client(ci, software.NewKEM, sp, server.TailcatAddr())
	legacy := tailcat.NewClient(server.TailcatAddr())
	legacy.Logf = t.Logf
	legacyCtx, stopLegacy := context.WithTimeout(ctx, 750*time.Millisecond)
	_, legacyErr := legacy.Ping(legacyCtx)
	stopLegacy()
	legacy.Close()
	if legacyErr == nil || len(server.Status().Peer) != 0 {
		t.Fatal("legacy Meow bypassed PQ authentication")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.Logf = t.Logf
	conn, err := client.DialTCPPort(ctx, 2222)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("quantumcat"), 4096)
	go func() { conn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("tunnel corrupted stream")
	}
	if !droppedHello.Load() || !droppedAck.Load() {
		t.Fatal("loss scenarios not exercised")
	}
	// A second invocation must get an independent PSK without disrupting the first.
	second, err := Client(ci, software.NewKEM, sp, server.TailcatAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.Logf = t.Logf
	secondConn, err := second.DialTCPPort(ctx, 2222)
	if err != nil {
		t.Fatal(err)
	}
	defer secondConn.Close()
	secondConn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = secondConn.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	two := make([]byte, 3)
	if _, err = io.ReadFull(secondConn, two); err != nil || string(two) != "two" {
		t.Fatalf("second session: %q %v", two, err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 3)
	if _, err = io.ReadFull(conn, one); err != nil || string(one) != "one" {
		t.Fatalf("first session disrupted: %q %v", one, err)
	}
	revoked.Store(true)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		st := server.Status()
		if len(st.Peer) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("revoked WireGuard peer remained installed")
}

// memoryTUN exercises the real WireGuard device's TUN packet path without
// changing the test host's routes or requiring root.
type memoryTUN struct {
	in, out chan []byte
	done    chan struct{}
	events  chan tun.Event
	once    sync.Once
}

func newMemoryTUN() *memoryTUN {
	return &memoryTUN{in: make(chan []byte, 16), out: make(chan []byte, 16), done: make(chan struct{}), events: make(chan tun.Event)}
}
func (t *memoryTUN) File() *os.File           { return nil }
func (t *memoryTUN) Name() (string, error)    { return "memory", nil }
func (t *memoryTUN) MTU() (int, error)        { return 1280, nil }
func (t *memoryTUN) BatchSize() int           { return 1 }
func (t *memoryTUN) Events() <-chan tun.Event { return t.events }
func (t *memoryTUN) Close() error             { t.once.Do(func() { close(t.done); close(t.events) }); return nil }
func (t *memoryTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	select {
	case <-t.done:
		return 0, io.EOF
	case p := <-t.in:
		if len(packets) == 0 || len(slab) < len(p)+2*tun.ReadPacketSpacing {
			return 0, tun.ErrTooManySegments
		}
		offset := tun.ReadPacketSpacing
		packets[0] = tun.ReadPacket{Offset: offset, Size: copy(slab[offset:], p)}
		return 1, nil
	}
}
func (t *memoryTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		select {
		case <-t.done:
			return 0, io.EOF
		case t.out <- append([]byte(nil), b[offset:]...):
		}
	}
	return len(bufs), nil
}
func TestIPModeHostPackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	relay := derpserver.New(key.NewNode(), t.Logf)
	httpRelay := httptest.NewTLSServer(derpserver.Handler(relay))
	defer httpRelay.Close()
	defer relay.Close()
	stun, closeSTUN := stuntest.ServeWithPacketListener(t, nettype.Std{})
	defer closeSTUN()
	si, _ := software.Generate()
	ci, _ := software.Generate()
	sp, _ := si.PublicKey(ctx)
	cp, _ := ci.PublicKey(ctx)
	server := Server(si, sp, key.NewNode(), func(yield func(protocol.PeerID, []byte) bool) { yield(protocol.ID(cp), cp) })
	server.Region = &tailcfg.DERPRegion{RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{Name: "test", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: httpRelay.Listener.Addr().(*net.TCPAddr).Port, STUNPort: stun.Port, STUNTestIP: "127.0.0.1", InsecureForTests: true}}}
	st := newMemoryTUN()
	server.TUN = st
	server.Logf = t.Logf
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	c, err := Client(ci, software.NewKEM, sp, server.TailcatAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ct := newMemoryTUN()
	c.TUN = ct
	c.Logf = t.Logf
	startupCtx, stopStartup := context.WithTimeout(ctx, 45*time.Second)
	_, err = c.Ping(startupCtx)
	stopStartup()
	if err != nil {
		t.Fatalf("IP-mode bootstrap: %v", err)
	}
	packetCtx, stopPackets := context.WithTimeout(ctx, 20*time.Second)
	defer stopPackets()
	local := tailcat.NodeAddress(c.PublicKey()).As16()
	remote := tailcat.NodeAddress(server.Key.Public()).As16()
	// IPv6 + UDP. The memory device tests packet transport, not an OS UDP stack.
	packet := make([]byte, 52)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 12)
	packet[6] = 17
	packet[7] = 64
	copy(packet[8:24], local[:])
	copy(packet[24:40], remote[:])
	binary.BigEndian.PutUint16(packet[40:42], 40000)
	binary.BigEndian.PutUint16(packet[42:44], 9000)
	binary.BigEndian.PutUint16(packet[44:46], 12)
	copy(packet[48:], "qcat")
	// IPv6 UDP pseudoheader checksum.
	sum := uint32(12 + 17)
	for j := 8; j < 40; j += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[j : j+2]))
	}
	for j := 40; j < len(packet); j += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[j : j+2]))
	}
	for sum > 65535 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[46:48], ^uint16(sum))
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-packetCtx.Done():
			t.Fatalf("TUN packet did not traverse authenticated WireGuard after bootstrap: %v", packetCtx.Err())
		case <-ticker.C:
			select {
			case ct.in <- packet:
			case <-packetCtx.Done():
				t.Fatalf("TUN injection blocked: %v", packetCtx.Err())
			}
		case got := <-st.out:
			if bytes.Equal(got, packet) {
				return
			}
		}
	}
}
