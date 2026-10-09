// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
	"testing"
	"time"
)

func pingRejectedForTest(t testing.TB, s *Server, c *Client) {
	t.Helper()
	WaitForDERPForTest(t, s, c)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.Ping(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ping from disallowed client = %v; want context deadline exceeded", err)
	}
}

// TestAllowClient checks that Server.AllowClient admits and rejects
// clients, is asked once per admission rather than on every meow,
// and may block and call back into the Server without deadlocking.
func TestAllowClient(t *testing.T) {
	t.Parallel()

	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	approved := key.NewNode()
	rejected := key.NewNode()
	slow := key.NewNode()

	var (
		mu       sync.Mutex
		calls    = map[key.NodePublic]int{}
		inFlight = map[key.NodePublic]bool{}
	)
	var s *Server
	s = &Server{
		Logf:   mkLogger(t, "server"),
		Region: reg,
		AllowClient: func(k key.NodePublic) bool {
			mu.Lock()
			calls[k]++
			if inFlight[k] {
				t.Errorf("concurrent AllowClient calls for %v", k)
			}
			inFlight[k] = true
			mu.Unlock()
			defer func() {
				mu.Lock()
				defer mu.Unlock()
				inFlight[k] = false
			}()
			if k == slow.Public() {
				// Outlast a meow retry, so a second meow arrives
				// while this one is pending, and take the backend
				// lock via Status to prove the hook runs without it.
				time.Sleep(1500 * time.Millisecond)
				s.Status()
			}
			return k != rejected.Public()
		},
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	newClient := func(name string, k key.NodePrivate) *Client {
		c := &Client{Server: s.TailcatAddr(), Key: k, Logf: mkLogger(t, name)}
		t.Cleanup(func() { c.Close() })
		return c
	}
	callsFor := func(k key.NodePublic) int {
		mu.Lock()
		defer mu.Unlock()
		return calls[k]
	}

	// An approved key is admitted, and once connected the client's
	// later pings are acknowledged without asking again.
	approvedClient := newClient("approved", approved)
	PingForTest(t, s, approvedClient)
	PingForTest(t, s, approvedClient)
	if n := callsFor(approved.Public()); n != 1 {
		t.Errorf("AllowClient called %d times for the approved key; want 1", n)
	}

	// A rejected key gets no reply, but the hook was consulted.
	pingRejectedForTest(t, s, newClient("rejected", rejected))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for callsFor(rejected.Public()) < 1 {
		select {
		case <-ctx.Done():
			t.Fatal("AllowClient never called for the rejected key")
		case <-time.After(time.Millisecond):
		}
	}

	// A slow hook delays only its own client, which is still admitted.
	// Meows arriving while the hook is pending are dropped rather than
	// starting a second call.
	PingForTest(t, s, newClient("slow", slow))
	if n := callsFor(slow.Public()); n != 1 {
		t.Errorf("AllowClient called %d times for the slow key; want 1", n)
	}
}

// TestDisconnectClient checks that dropping a connected client
// removes it from the server and stops its traffic, while leaving
// other clients untouched.
func TestDisconnectClient(t *testing.T) {
	t.Parallel()

	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	var allow KeySet
	s := &Server{Key: key.NewNode(), Logf: mkLogger(t, "server"), Region: reg, AllowClient: allow.Contains}
	t.Cleanup(func() { s.Close() })
	s.OnTCP = func(port uint16) func(net.Conn) {
		if port != 80 {
			return nil
		}
		return func(c net.Conn) {
			io.WriteString(c, "hello\n")
			c.Close()
		}
	}
	if s.DisconnectClient(key.NewNode().Public()) {
		t.Error("DisconnectClient before Start reported a connected client")
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	revokedKey := key.NewNode()
	revoked := &Client{Server: s.TailcatAddr(), Key: revokedKey, Logf: mkLogger(t, "revoked")}
	t.Cleanup(func() { revoked.Close() })
	kept := &Client{Server: s.TailcatAddr(), Logf: mkLogger(t, "kept")}
	t.Cleanup(func() { kept.Close() })
	allow.Add(revoked.PublicKey())
	allow.Add(kept.PublicKey())

	PingForTest(t, s, revoked)
	PingForTest(t, s, kept)
	if _, ok := s.Status().Peer[revoked.PublicKey()]; !ok {
		t.Fatal("revoked client not a peer before removal")
	}

	// Revoke: stop admitting the key, then drop the live client.
	allow.Remove(revoked.PublicKey())
	if !s.DisconnectClient(revoked.PublicKey()) {
		t.Fatal("DisconnectClient reported the revoked client as not connected")
	}
	if s.DisconnectClient(revoked.PublicKey()) {
		t.Fatal("second DisconnectClient reported the revoked client as still connected")
	}

	if _, ok := s.Status().Peer[revoked.PublicKey()]; ok {
		t.Fatal("revoked client still reported as a peer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if conn, err := revoked.DialTCPPort(ctx, 80); err == nil {
		conn.Close()
		t.Fatal("revoked client dialed the server after removal")
	}
	cancel()

	// A fresh client presenting the revoked key is ignored at the meow.
	again := &Client{Server: s.TailcatAddr(), Key: revokedKey, Logf: mkLogger(t, "again")}
	t.Cleanup(func() { again.Close() })
	pingRejectedForTest(t, s, again)

	// The other client is unaffected.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := kept.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("kept client DialTCPPort = %v", err)
	}
	if got, _ := io.ReadAll(conn); string(got) != "hello\n" {
		t.Fatalf("kept client read %q; want %q", got, "hello\n")
	}
}

// Bootstrap callbacks remain serialized while user admission decisions may
// block independently. Feed frames directly into the bounded DERP queue so the
// tests control the interleavings rather than relying on network retries.
func newBootstrapTestServer(t *testing.T) *Server {
	t.Helper()
	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	s := &Server{Logf: mkLogger(t, "server"), Region: dm.Regions[1]}
	t.Cleanup(func() { s.Close() })
	return s
}

func awaitBootstrapEvent[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for bootstrap event")
		var zero T
		return zero
	}
}

func TestBootstrapAdmissionDoesNotBlockWorker(t *testing.T) {
	s := newBootstrapTestServer(t)
	slow, fast := key.NewNode().Public(), key.NewNode().Public()
	entered := make(chan struct{})
	returned := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var slowCalls atomic.Int32
	s.AllowClient = func(k key.NodePublic) bool {
		if k == slow {
			defer close(returned)
			if slowCalls.Add(1) == 1 {
				close(entered)
			}
			<-release
		}
		// Admission hooks may call Server methods without deadlocking.
		s.Status()
		return true
	}
	type installation struct {
		src key.NodePublic
		ok  bool
	}
	installed := make(chan installation, 16)
	removed := make(chan key.NodePublic, 16)
	var valid atomic.Bool
	valid.Store(true)
	disco := key.NewDisco().Public()
	s.Bootstrap = func(src key.NodePublic, _ []byte) ([]byte, *AuthenticatedPeer) {
		return nil, &AuthenticatedPeer{
			Identity: src.Raw32(), Disco: disco, PSK: NewPresharedKey(),
			Valid:     func() bool { return valid.Load() },
			Installed: func(ok bool) { installed <- installation{src, ok} },
		}
	}
	s.OnTunnelPeer = func(k key.NodePublic, add bool) error {
		if !add {
			removed <- k
		}
		return nil
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	send := func(k key.NodePublic) { s.lb.onDERPRecv(1, k, []byte("QCATtest")) }
	send(slow)
	awaitBootstrapEvent(t, entered)
	send(slow) // A retry must not start another admission for this key.
	send(fast)
	if got := awaitBootstrapEvent(t, installed); got.src != fast || !got.ok {
		t.Fatalf("fast client installation = %+v", got)
	}
	send(fast)
	if got := awaitBootstrapEvent(t, installed); got.src != fast || !got.ok {
		t.Fatalf("fast client renewal = %+v", got)
	}
	valid.Store(false)
	if got := awaitBootstrapEvent(t, removed); got != fast {
		t.Fatalf("expired peer = %v; want fast client", got)
	}
	// Close must finish without waiting for an uncooperative AllowClient.
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	awaitBootstrapEvent(t, closed)
	if got := awaitBootstrapEvent(t, installed); got.src != slow || got.ok {
		t.Fatalf("pending admission on shutdown = %+v", got)
	}
	releaseOnce.Do(func() { close(release) })
	awaitBootstrapEvent(t, returned)
	if slowCalls.Load() != 1 {
		t.Fatalf("slow hook calls = %d; want 1", slowCalls.Load())
	}
	s.lb.mu.Lock()
	defer s.lb.mu.Unlock()
	if len(s.lb.clients) != 0 || len(s.lb.peerPSKs) != 0 {
		t.Fatal("pending admission retained peer state")
	}
}

func TestBootstrapDisconnectOrdersRouteCallbacks(t *testing.T) {
	s := newBootstrapTestServer(t)
	client := key.NewNode().Public()
	adding := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var route atomic.Bool
	callbacks := make(chan bool, 4)
	installed := make(chan bool, 4)
	s.Bootstrap = func(key.NodePublic, []byte) ([]byte, *AuthenticatedPeer) {
		return nil, &AuthenticatedPeer{
			Identity: [32]byte{1}, Disco: key.NewDisco().Public(), PSK: NewPresharedKey(),
			Valid: func() bool { return true }, Installed: func(ok bool) { installed <- ok },
		}
	}
	s.OnTunnelPeer = func(k key.NodePublic, add bool) error {
		if k != client {
			t.Errorf("route callback for unexpected peer %v", k)
		}
		if add {
			close(adding)
			<-release // Disconnect runs while the route is not installed yet.
		}
		route.Store(add)
		callbacks <- add
		return nil
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	s.lb.onDERPRecv(1, client, []byte("QCATtest"))
	awaitBootstrapEvent(t, adding)
	disconnecting := make(chan struct{})
	disconnected := make(chan bool, 1)
	go func() { close(disconnecting); disconnected <- s.DisconnectClient(client) }()
	awaitBootstrapEvent(t, disconnecting)
	select {
	case result := <-disconnected:
		t.Fatalf("disconnect finished before route installation: %v", result)
	case <-time.After(100 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	if !awaitBootstrapEvent(t, installed) {
		t.Fatal("route installation failed")
	}
	if !awaitBootstrapEvent(t, disconnected) {
		t.Fatal("installed client was not disconnected")
	}
	if !awaitBootstrapEvent(t, callbacks) || awaitBootstrapEvent(t, callbacks) {
		t.Fatal("route callbacks were not ordered add, remove")
	}
	if route.Load() {
		t.Fatal("disconnected client's route remained installed")
	}
	s.lb.mu.Lock()
	defer s.lb.mu.Unlock()
	if len(s.lb.clients) != 0 || len(s.lb.peerPSKs) != 0 || len(s.lb.peerValid) != 0 || len(s.lb.peerOwners) != 0 || len(s.lb.peerInstalled) != 0 {
		t.Fatal("disconnected client retained authentication state")
	}
}

func TestBootstrapDisconnectCancelsPendingAdmission(t *testing.T) {
	s := newBootstrapTestServer(t)
	client := key.NewNode().Public()
	installed := make(chan bool, 2)
	var calls atomic.Int32
	s.AllowClient = func(k key.NodePublic) bool {
		// A hook may revoke its own in-flight admission without deadlocking.
		if calls.Add(1) == 1 && s.DisconnectClient(k) {
			t.Error("pending client reported as connected")
		}
		return true
	}
	s.Bootstrap = func(key.NodePublic, []byte) ([]byte, *AuthenticatedPeer) {
		return nil, &AuthenticatedPeer{
			Identity: [32]byte{1}, Disco: key.NewDisco().Public(), PSK: NewPresharedKey(),
			Valid: func() bool { return true }, Installed: func(ok bool) { installed <- ok },
		}
	}
	var routes atomic.Int32
	s.OnTunnelPeer = func(key.NodePublic, bool) error { routes.Add(1); return nil }
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	s.lb.onDERPRecv(1, client, []byte("QCATtest"))
	if awaitBootstrapEvent(t, installed) || routes.Load() != 0 {
		t.Fatal("cancelled admission installed a peer route")
	}
	// Once the cancelled hook has returned, a fresh admission can proceed.
	s.lb.onDERPRecv(1, client, []byte("QCATtest"))
	if !awaitBootstrapEvent(t, installed) || routes.Load() != 1 || calls.Load() != 2 {
		t.Fatal("fresh admission did not install exactly once")
	}
}

func TestLegacyAdmissionCancellation(t *testing.T) {
	for _, action := range []string{"disconnect", "close"} {
		t.Run(action, func(t *testing.T) {
			s := newBootstrapTestServer(t)
			client := key.NewNode().Public()
			disco := key.NewDisco().Public()
			entered := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			var allowed atomic.Bool
			allowed.Store(true)
			var calls atomic.Int32
			s.AllowClient = func(key.NodePublic) bool {
				// Capture the old policy decision before revocation, then delay its
				// return until after disconnect/shutdown has completed.
				approved := allowed.Load()
				if calls.Add(1) == 1 {
					close(entered)
					<-release
				}
				return approved
			}
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			result := make(chan bool, 1)
			go func() { result <- s.lb.onMeow(client, disco) }()
			awaitBootstrapEvent(t, entered)
			allowed.Store(false)
			if action == "disconnect" {
				if s.DisconnectClient(client) {
					t.Fatal("pending legacy client reported as connected")
				}
			} else {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			// Cancellation must retain per-key serialization until the hook returns.
			if s.lb.onMeow(client, disco) || calls.Load() != 1 {
				t.Fatal("retry started a second admission while the old hook was pending")
			}
			releaseOnce.Do(func() { close(release) })
			if awaitBootstrapEvent(t, result) {
				t.Fatal("stale approval installed a revoked legacy peer")
			}
			s.lb.mu.Lock()
			peers, pending := len(s.lb.clients), len(s.lb.pendingAllow)
			s.lb.mu.Unlock()
			if peers != 0 || pending != 0 {
				t.Fatalf("retained peers=%d pending=%d", peers, pending)
			}
			if action == "disconnect" {
				if s.lb.onMeow(client, disco) {
					t.Fatal("fresh admission ignored updated rejection policy")
				}
				allowed.Store(true)
				if !s.lb.onMeow(client, disco) {
					t.Fatal("fresh approved admission was not installed")
				}
			} else if s.lb.onMeow(client, disco) {
				t.Fatal("closed server admitted a new peer")
			}
		})
	}
}
