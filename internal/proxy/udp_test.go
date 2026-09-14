package proxy

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func udpEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { echo.Close(); <-done })
	return echo
}
func localUDP(t *testing.T, addr net.Addr) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, addr.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func echoPacket(t *testing.T, c *net.UDPConn, p []byte) {
	t.Helper()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(p); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 65535)
	n, err := c.Read(out)
	if err != nil || !bytes.Equal(out[:n], p) {
		t.Fatalf("echo size %d -> %d, err %v", len(p), n, err)
	}
}
func TestUDPForwardDatagramsAndShutdown(t *testing.T) {
	echo := udpEcho(t)
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ForwardUDP(ctx, local, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp4", echo.LocalAddr().String())
		}, time.Minute)
	}()
	a, b := localUDP(t, local.LocalAddr()), localUDP(t, local.LocalAddr())
	// Stay within macOS's kernel UDP limit; framing's full limit is tested separately.
	for _, size := range []int{0, 1, 1200, 4096, 8192} {
		echoPacket(t, a, bytes.Repeat([]byte{0xa1}, size))
		echoPacket(t, b, bytes.Repeat([]byte{0xb2}, size))
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("forwarder leaked after cancellation")
	}
}

type countedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}
func TestUDPIdleFlowRecreated(t *testing.T) {
	echo := udpEcho(t)
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	closed := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- ForwardUDP(ctx, local, func(ctx context.Context) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, "udp4", echo.LocalAddr().String())
			if err == nil && calls.Add(1) == 1 {
				return &countedConn{Conn: c, closed: closed}, nil
			}
			return c, err
		}, 100*time.Millisecond)
	}()
	c := localUDP(t, local.LocalAddr())
	echoPacket(t, c, []byte("first"))
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle flow remained open")
	}
	// Close notification precedes removing the old mapping by a few instructions;
	// retry datagrams just as a loss-tolerant UDP application would.
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		c.Write([]byte("second"))
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() != 2 {
		t.Fatal("idle sender did not get a new flow")
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "second" {
		t.Fatalf("replacement flow: %q %v", buf[:n], err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown blocked")
	}
}
func TestUDPServicesRejectUnpublishedPorts(t *testing.T) {
	handler, err := UDPServices(context.Background(), map[uint16]string{60001: "127.0.0.1:60001"})
	if err != nil {
		t.Fatal(err)
	}
	if handler(60001) == nil || handler(60002) != nil || handler(0) != nil {
		t.Fatal("UDP destination policy not enforced")
	}
}
