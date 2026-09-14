package transport

import (
	"bytes"
	"context"
	"net"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ekarulf/quantumcat/internal/crypto/provider/software"
	"github.com/ekarulf/quantumcat/internal/protocol"
	"github.com/ekarulf/quantumcat/internal/proxy"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

func TestPublishedUDPForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	relay := derpserver.New(key.NewNode(), t.Logf)
	httpRelay := httptest.NewTLSServer(derpserver.Handler(relay))
	defer httpRelay.Close()
	defer relay.Close()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	var forbiddenDeliveries atomic.Int32
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		tokens := map[string]byte{}
		buffer := make([]byte, 65535)
		for {
			n, addr, err := echo.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if string(buffer[:n]) == "unpublished" {
				forbiddenDeliveries.Add(1)
			}
			token, ok := tokens[addr.String()]
			if !ok {
				token = byte(len(tokens) + 1)
				tokens[addr.String()] = token
			}
			echo.WriteToUDP(append([]byte{token}, buffer[:n]...), addr)
		}
	}()
	defer func() { echo.Close(); <-echoDone }()
	si, _ := software.Generate()
	ci, _ := software.Generate()
	sp, _ := si.PublicKey(ctx)
	cp, _ := ci.PublicKey(ctx)
	server := Server(si, sp, key.NewNode(), func(id protocol.PeerID) []byte {
		if id == protocol.ID(cp) {
			return cp
		}
		return nil
	})
	server.Region = &tailcfg.DERPRegion{RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{Name: "test", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: httpRelay.Listener.Addr().(*net.TCPAddr).Port, STUNPort: -1, InsecureForTests: true}}}
	server.Logf = t.Logf
	server.OnUDP, err = proxy.UDPServices(ctx, map[uint16]string{60001: echo.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	server.ServedUDPPorts = []filter.PortRange{{First: 60001, Last: 60001}}
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	c, err := Client(ci, software.NewKEM, sp, server.TailcatAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Logf = t.Logf
	if _, err = c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	forwardCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() {
		done <- proxy.ForwardUDP(forwardCtx, local, func(ctx context.Context) (net.Conn, error) {
			conn, err := c.DialUDPPort(ctx, 60001)
			if err != nil {
				return nil, err
			}
			return proxy.FramedUDP(conn), nil
		}, time.Minute)
	}()
	defer func() {
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("UDP forwarder did not shut down")
		}
	}()
	a, err := net.DialUDP("udp4", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.DialUDP("udp4", nil, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	sent := map[*net.UDPConn][][]byte{}
	exchange := func(socket *net.UDPConn, payload []byte) byte {
		t.Helper()
		buf := make([]byte, 65535)
		sent[socket] = append(sent[socket], append([]byte{}, payload...))
		// Initial UDP datagrams may be dropped while WireGuard establishes its session.
		for attempt := 0; attempt < 10; attempt++ {
			socket.SetDeadline(time.Now().Add(500 * time.Millisecond))
			if _, err := socket.Write(payload); err != nil {
				t.Fatal(err)
			}
			for {
				n, err := socket.Read(buf)
				if err != nil {
					break
				}
				if n == len(payload)+1 && bytes.Equal(buf[1:n], payload) {
					return buf[0]
				}
				// UDP retries can leave delayed replies to an earlier exchange queued.
				known := false
				if n > 0 {
					for _, old := range sent[socket] {
						if bytes.Equal(buf[1:n], old) {
							known = true
							break
						}
					}
				}
				if !known {
					t.Fatalf("datagram mismatch: sent %d bytes, received %d", len(payload), n)
				}
			}
		}
		t.Fatal("no UDP response through WireGuard")
		return 0
	}
	// Zero-length datagrams must open a flow and reach the destination.
	tokenA := exchange(a, nil)
	tokenB := exchange(b, []byte("client B"))
	if tokenA == tokenB {
		t.Fatal("local senders shared the same remote UDP socket")
	}
	for _, size := range []int{1, 1200, 1220, 1221, 1232, 1280, 4096, 8192} {
		if token := exchange(a, bytes.Repeat([]byte{0xa1}, size)); token != tokenA {
			t.Fatal("client A changed flows")
		}
		if token := exchange(b, bytes.Repeat([]byte{0xb2}, size)); token != tokenB {
			t.Fatal("client B changed flows")
		}
	}
	rawDenied, err := c.DialUDPPort(ctx, 60002)
	if err != nil {
		t.Fatal(err)
	}
	denied := proxy.FramedUDP(rawDenied)
	defer denied.Close()
	denied.SetDeadline(time.Now().Add(300 * time.Millisecond))
	denied.Write([]byte("unpublished"))
	buf := make([]byte, 128)
	if _, err = denied.Read(buf); err == nil {
		t.Fatal("unpublished UDP service answered")
	}
	if forbiddenDeliveries.Load() != 0 {
		t.Fatal("unpublished service reached configured destination")
	}
}
