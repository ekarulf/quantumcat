package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ekarulf/quantumcat/internal/config"
	"github.com/ekarulf/quantumcat/internal/control"
	"github.com/ekarulf/quantumcat/internal/crypto/provider/se"
	"github.com/ekarulf/quantumcat/internal/protocol"
	"github.com/ekarulf/quantumcat/internal/proxy"
	"github.com/ekarulf/quantumcat/internal/transport"
	"github.com/ekarulf/quantumcat/internal/tunnel"
	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

const usage = `Quantumcat — authenticated point-to-point networking

qcat [--config DIR] identity init [--name NAME] [--provider software|secure-enclave]
qcat [--config DIR] identity show
qcat [--config DIR] peer add NAME FILE.qpeer
qcat [--config DIR] peer list|show NAME|remove NAME
qcat [--config DIR] serve [--tcp PORT=HOST:PORT] [--udp PORT=HOST:PORT]
                         [--udp FIRST:LAST=HOST:BASE]
                         [--allow-target HOST:PORT] [--udp-idle-timeout 2m]
                         [--region ID] [--derp-map URL] [--export FILE.qpeer]
qcat [--config DIR] forward PEER LOCALPORT:HOST:PORT
qcat [--config DIR] forward --udp [--udp-idle-timeout 2m] PEER LOCALPORT:TUNNELPORT
qcat [--config DIR] socks [--listen 127.0.0.1:1080] PEER
qcat [--config DIR] connect PEER PORT
qcat [--config DIR] mosh [--ssh-host HOST] [--server-port PORT] [--tunnel-port PORT]
                        [--local-port 0] [--mosh-server PATH] PEER [-- COMMAND...]
qcat [--config DIR] up PEER
qcat [--config DIR] serve --tun [--export FILE.qpeer]
qcat [--config DIR] status
qcat [--config DIR] down [PEER|serve]
qcat debug

Pair identity show output out of band; serve --export includes public reachability.
Flags for each command precede positional arguments. Ctrl-C closes the tunnel.
`

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qcat:", err)
		os.Exit(1)
	}
}
func emit(v any) error { e := json.NewEncoder(os.Stdout); e.SetIndent("", "  "); return e.Encode(v) }
func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	return f
}
func run(ctx context.Context, args []string) error {
	f := flags("qcat")
	dir := f.String("config", config.DefaultDir(), "configuration directory")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(usage)
			return nil
		}
		return err
	}
	args = f.Args()
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	s := config.Store{Dir: *dir}
	switch args[0] {
	case "help":
		fmt.Print(usage)
		return nil
	case "identity":
		return identity(ctx, s, args[1:])
	case "peer":
		return peers(s, args[1:])
	case "serve":
		return serve(ctx, s, args[1:])
	case "mosh":
		return mosh(ctx, s, args[1:])
	case "forward", "socks", "connect", "up":
		return client(ctx, s, args[0], args[1:])
	case "status":
		if len(args) != 1 {
			return errors.New("status takes no arguments")
		}
		status, err := control.Query(s.Dir, "", "status")
		if err != nil {
			return err
		}
		return emit(status)
	case "down":
		if len(args) > 2 {
			return errors.New("down takes an optional peer or runtime name")
		}
		name := ""
		if len(args) == 2 {
			name = args[1]
		}
		result, err := control.Query(s.Dir, name, "stop")
		if err != nil {
			return err
		}
		return emit(result)
	case "debug":
		h, err := se.Open()
		if err != nil {
			return err
		}
		defer h.Close()
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		caps, err := h.Capabilities(ctx)
		if err != nil {
			return err
		}
		fmt.Println(string(caps))
		return nil
	default:
		return fmt.Errorf("unknown command %q; use qcat help", args[0])
	}
}
func identity(ctx context.Context, s config.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("identity requires init or show")
	}
	if args[0] == "init" {
		f := flags("identity init")
		name := f.String("name", "default", "device name")
		kind := f.String("provider", "", "key provider")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		if err := s.Init(ctx, *name, *kind); err != nil {
			return err
		}
	} else if args[0] != "show" || len(args) != 1 {
		return errors.New("identity requires init or show")
	}
	i, _, meta, close, err := s.Identity(ctx)
	if err != nil {
		return err
	}
	defer close()
	pub, err := i.PublicKey(ctx)
	if err != nil {
		return err
	}
	return emit(config.Peer{Version: 1, Name: meta.Name, PeerID: protocol.ID(pub).String(), PublicKey: pub})
}
func peers(s config.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("peer requires add, list, show or remove")
	}
	switch {
	case args[0] == "add" && len(args) == 3:
		return s.Add(args[1], args[2])
	case args[0] == "remove" && len(args) == 2:
		if err := s.Remove(args[1]); err != nil {
			return err
		}
		fmt.Println("Peer removed; recoverable from peers/" + args[1] + ".qpeer.revoked. Running servers revoke sessions within two seconds.")
		return nil
	case args[0] == "show" && len(args) == 2:
		p, err := s.Peer(args[1])
		if err != nil {
			return err
		}
		return emit(p)
	case args[0] == "list" && len(args) == 1:
		p, err := s.Peers()
		if err != nil {
			return err
		}
		return emit(p)
	default:
		return errors.New("invalid peer arguments")
	}
}

type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }
func serve(ctx context.Context, s config.Store, args []string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	f := flags("serve")
	var tcp, udp, allow repeated
	f.Var(&tcp, "tcp", "PORT=HOST:PORT (repeatable)")
	f.Var(&udp, "udp", "UDP PORT=HOST:PORT or FIRST:LAST=HOST:BASE (repeatable, explicit destinations only)")
	udpIdle := f.Duration("udp-idle-timeout", proxy.DefaultUDPIdleTimeout, "close inactive UDP flows after this duration")
	f.Var(&allow, "allow-target", "SOCKS target (repeatable, exact match)")
	region := f.Int("region", 0, "DERP region ID")
	dm := f.String("derp-map", "", "DERP map URL")
	export := f.String("export", "", "new public .qpeer file")
	tunMode := f.Bool("tun", false, "use an OS TUN with authenticated peer host routes")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *udpIdle <= 0 {
		return errors.New("UDP idle timeout must be positive")
	}
	udpTargets, err := udpServiceSpecs(udp)
	if err != nil {
		return err
	}
	targets := map[uint16]string{}
	allowed := map[string]bool{}
	for _, entry := range tcp {
		p, target, ok := strings.Cut(entry, "=")
		if !ok {
			return errors.New("--tcp requires PORT=HOST:PORT")
		}
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil || port < 2 {
			return errors.New("served port must be 2–65535; port 1 is reserved")
		}
		if err = proxy.ValidateTarget(target); err != nil {
			return err
		}
		if _, exists := targets[uint16(port)]; exists {
			return fmt.Errorf("duplicate TCP service port %d", port)
		}
		targets[uint16(port)] = target
		allowed[target] = true
	}
	for _, target := range allow {
		if err := proxy.ValidateTarget(target); err != nil {
			return err
		}
		allowed[target] = true
	}
	if len(allowed) == 0 && len(udpTargets) == 0 && !*tunMode {
		return errors.New("specify at least one --tcp, --udp or --allow-target")
	}
	if *tunMode && (len(allowed) > 0 || len(udpTargets) > 0) {
		return errors.New("--tun cannot be combined with forwarding services")
	}
	i, _, meta, close, err := s.Identity(ctx)
	if err != nil {
		return err
	}
	defer close()
	pub, err := i.PublicKey(ctx)
	if err != nil {
		return err
	}
	paired, err := s.Peers()
	if err != nil {
		return err
	}
	var mu sync.RWMutex
	authorized := map[protocol.PeerID][]byte{}
	for _, p := range paired {
		authorized[protocol.ID(p.PublicKey)] = p.PublicKey
	}
	server := transport.Server(i, pub, meta.Node, func(id protocol.PeerID) []byte { mu.RLock(); defer mu.RUnlock(); return authorized[id] })
	if *tunMode {
		tun, err := tunnel.Open()
		if err != nil {
			return err
		}
		defer tun.Close()
		if err = tun.Configure(tailcat.NodeAddress(meta.Node.Public())); err != nil {
			return err
		}
		server.TUN = tun.Device
		server.OnTunnelPeer = func(k key.NodePublic, add bool) error { return tun.Peer(tailcat.NodeAddress(k), add) }
		fmt.Fprintln(os.Stderr, "TUN", tun.Name, tailcat.NodeAddress(meta.Node.Public()))
	}
	server.RegionID = tailcfg.DERPRegionID(*region)
	server.DERPMapURL = *dm
	server.Logf = func(string, ...any) {}
	if len(udpTargets) > 0 {
		server.OnUDP, err = proxy.UDPServices(ctx, udpTargets)
		if err != nil {
			return err
		}
		server.UDPIdleTimeout = *udpIdle
		for port := range udpTargets {
			server.ServedUDPPorts = append(server.ServedUDPPorts, filter.PortRange{First: port, Last: port})
		}
	}
	server.ServedTCPPorts = publishedTCPPorts(targets)
	server.OnTCP = func(port uint16) func(net.Conn) {
		if port == 1 {
			return func(c net.Conn) { proxy.Serve(c, func(target string) bool { return allowed[target] }) }
		}
		target, ok := targets[port]
		if !ok {
			return nil
		}
		return func(c net.Conn) {
			defer c.Close()
			out, err := net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				return
			}
			defer out.Close()
			tailcat.ProxyConns(c, out)
		}
	}
	if err = server.Start(); err != nil {
		return err
	}
	defer server.Close()
	closeControl, err := control.Start(ctx, s.Dir, "serve", func() any { return server.Status() }, cancel)
	if err != nil {
		return err
	}
	defer closeControl()
	descriptor := config.Peer{Version: 1, Name: meta.Name, PeerID: protocol.ID(pub).String(), PublicKey: pub, Endpoint: server.TailcatAddr()}
	if err = descriptor.Validate(); err != nil {
		return err
	}
	if *export != "" {
		if err = config.WriteNew(*export, descriptor); err != nil {
			return err
		}
	}
	if err = emit(descriptor); err != nil {
		return err
	}
	var identityDone <-chan struct{}
	if monitored, ok := i.(interface{ Done() <-chan struct{} }); ok {
		identityDone = monitored.Done()
	}
	// Reload pairing on every tick. Transient failures retain the last-known-good
	// set; persistent failures still fail closed.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var reloadState authorizationReload
	for {
		select {
		case <-identityDone:
			return errors.New("identity helper exited; restart qcat to reload the identity")
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			next := reloadAuthorizations(s, os.Stderr, &reloadState, authorized)
			mu.Lock()
			authorized = next
			mu.Unlock()
		}
	}
}
func client(ctx context.Context, s config.Store, command string, args []string) error {
	ctx, cancel := clientContext(ctx)
	defer cancel()
	f := flags(command)
	listen := f.String("listen", "127.0.0.1:1080", "local SOCKS listen address")
	udp := f.Bool("udp", false, "forward UDP using LOCALPORT:TUNNELPORT")
	udpIdle := f.Duration("udp-idle-timeout", proxy.DefaultUDPIdleTimeout, "close inactive UDP flows after this duration")
	if err := f.Parse(args); err != nil {
		return err
	}
	args = f.Args()
	if len(args) < 1 {
		return errors.New("peer name required")
	}
	if *udp && command != "forward" {
		return errors.New("--udp is supported only by forward")
	}
	if *udpIdle <= 0 {
		return errors.New("UDP idle timeout must be positive")
	}
	var udpListen string
	var udpPort uint16
	if *udp {
		if len(args) != 2 {
			return errors.New("UDP forward requires PEER LOCALPORT:TUNNELPORT")
		}
		var err error
		udpListen, udpPort, err = udpForwardSpec(args[1])
		if err != nil {
			return err
		}
	}
	p, err := s.Peer(args[0])
	if err != nil {
		return err
	}
	if p.Endpoint == "" {
		return errors.New("peer has no endpoint; pair the server's serve --export descriptor")
	}
	i, kem, _, closeIdentity, err := s.Identity(ctx)
	if err != nil {
		return err
	}
	defer closeIdentity()
	c, err := transport.Client(i, kem, p.PublicKey, p.Endpoint)
	if err != nil {
		return err
	}
	defer c.Close()
	c.Logf = func(string, ...any) {}
	var tun *tunnel.Tunnel
	if command == "up" {
		if len(args) != 1 {
			return errors.New("up requires PEER")
		}
		tun, err = tunnel.Open()
		if err != nil {
			return err
		}
		defer tun.Close()
		c.TUN = tun.Device
		if err = tun.Configure(tailcat.NodeAddress(c.PublicKey())); err != nil {
			return err
		}
	}
	if _, err = c.Ping(ctx); err != nil {
		return err
	}
	renewCtx, stopRenewal := context.WithCancel(ctx)
	renewDone := make(chan struct{})
	var reportRenewalError func(error)
	if command != "connect" {
		reportRenewalError = func(err error) {
			fmt.Fprintln(os.Stderr, "qcat: tunnel recovery/renewal failed; retrying:", err)
		}
	}
	go func() {
		defer close(renewDone)
		transport.Maintain(renewCtx, c, reportRenewalError)
	}()
	defer func() { stopRenewal(); <-renewDone }()
	if command != "connect" {
		name := command + "-" + args[0]
		if *udp {
			_, port, _ := net.SplitHostPort(udpListen)
			name = "forward-udp-" + port + "-" + args[0]
		}
		closeControl, err := control.StartPeer(ctx, s.Dir, name, args[0], func() any { return c.Status() }, cancel)
		if err != nil {
			return err
		}
		defer closeControl()
	}
	if *udp {
		return forwardUDP(ctx, c, udpListen, udpPort, *udpIdle)
	}
	if command == "up" {
		ci, err := tailcat.ParseAddr(p.Endpoint)
		if err != nil {
			return err
		}
		addr := tailcat.NodeAddress(ci.ServerPublic.NodePublic)
		if err = tun.Peer(addr, true); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "TUN", tun.Name, "local", tailcat.NodeAddress(c.PublicKey()), "remote", addr)
		<-ctx.Done()
		return nil
	}
	if command == "connect" {
		if len(args) != 2 {
			return errors.New("connect requires PEER PORT")
		}
		port, err := strconv.ParseUint(args[1], 10, 16)
		if err != nil || port < 2 {
			return errors.New("invalid port")
		}
		conn, err := c.DialTCPPort(ctx, uint16(port))
		if err != nil {
			return err
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		go func() {
			io.Copy(conn, os.Stdin)
			if w, ok := conn.(interface{ CloseWrite() error }); ok {
				w.CloseWrite()
			}
		}()
		_, err = io.Copy(os.Stdout, conn)
		return err
	}
	var target string
	if command == "forward" {
		if len(args) != 2 {
			return errors.New("forward requires PEER LOCALPORT:HOST:PORT")
		}
		port, remote, ok := strings.Cut(args[1], ":")
		if !ok {
			return errors.New("invalid forwarding specification")
		}
		if err = proxy.ValidateTarget(remote); err != nil {
			return err
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return err
		}
		*listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(n)))
		target = remote
	} else if len(args) != 1 {
		return errors.New("socks requires PEER")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("local listener must use a loopback IP")
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	fmt.Fprintln(os.Stderr, "Listening on", ln.Addr())
	slots := make(chan struct{}, 128)
	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			local.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer local.Close()
			remote, err := c.DialTCPPort(ctx, 1)
			if err != nil {
				return
			}
			defer remote.Close()
			if target != "" {
				remote, err = proxy.Dial(ctx, remote, target)
				if err != nil {
					return
				}
			}
			tailcat.ProxyConns(local, remote)
		}()
	}
}
