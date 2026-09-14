package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ekarulf/quantumcat/internal/config"
	"github.com/ekarulf/quantumcat/internal/control"
	"github.com/ekarulf/quantumcat/internal/proxy"
	"github.com/ekarulf/quantumcat/internal/transport"
)

var moshConnect = regexp.MustCompile(`^MOSH CONNECT ([0-9]{1,5}) ([A-Za-z0-9/+]{22})$`)

// Never echo bootstrap output in an error: it may contain the session key.
type moshSession struct {
	port int
	key  string
}

func parseMoshConnect(output string, expectedPort int) (moshSession, error) {
	var session moshSession
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, "MOSH CONNECT") {
			continue
		}
		m := moshConnect.FindStringSubmatch(line)
		if m == nil || session.key != "" {
			return moshSession{}, errors.New("invalid or duplicate MOSH CONNECT response")
		}
		port, err := strconv.Atoi(m[1])
		if err != nil || port < 1 || port > 65535 || (expectedPort != 0 && port != expectedPort) {
			return moshSession{}, errors.New("mosh-server returned an invalid or unexpected port")
		}
		session = moshSession{port: port, key: m[2]}
	}
	if session.key == "" {
		return moshSession{}, errors.New("no MOSH CONNECT response; check the remote mosh-server installation")
	}
	return session, nil
}

func shellWord(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func moshServerCommand(server string, port int, command []string) string {
	words := []string{"new", "-i", "127.0.0.1"}
	if port != 0 {
		words = append(words, "-p", strconv.Itoa(port))
	}
	words = append(words, "-c", "256", "-l", "LANG=en_US.UTF-8")
	if len(command) > 0 {
		words = append(words, "--")
		words = append(words, command...)
	}
	for i := range words {
		words[i] = shellWord(words[i])
	}
	args := strings.Join(words, " ")
	if server != "" {
		return shellWord(server) + " " + args
	}
	// SSH non-interactive shells often omit Homebrew from PATH. Discover on
	// the remote host, without changing its shell configuration. An explicit
	// --mosh-server bypasses discovery and is never treated as shell code.
	script := "if command -v mosh-server >/dev/null 2>&1; then exec mosh-server " + args +
		"; elif [ -x /opt/homebrew/bin/mosh-server ]; then exec /opt/homebrew/bin/mosh-server " + args +
		"; elif [ -x /usr/local/bin/mosh-server ]; then exec /usr/local/bin/mosh-server " + args +
		"; else printf '%s\\n' 'mosh-server not found; install Mosh or use --mosh-server PATH' >&2; exit 127; fi"
	return "sh -c " + shellWord(script)
}

type boundedMoshOutput struct{ bytes.Buffer }

// Mosh's session key is 22 base64 characters. Redact base64-looking runs
// defensively even when a failing remote process includes the key in stderr.
var moshDiagnosticToken = regexp.MustCompile(`[A-Za-z0-9/+]{22,}={0,2}`)

func moshDiagnostic(stderr string) string {
	var lines []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.Contains(line, "MOSH CONNECT") {
			continue
		}
		line = strings.Map(func(r rune) rune {
			if r < 32 && r != '\t' || r == 127 {
				return -1
			}
			return r
		}, line)
		lines = append(lines, moshDiagnosticToken.ReplaceAllString(line, "[redacted]"))
	}
	diagnostic := strings.TrimSpace(strings.Join(lines, "\n"))
	if len(diagnostic) > 4096 {
		diagnostic = diagnostic[:4096] + "\n[truncated]"
	}
	return diagnostic
}

func (b *boundedMoshOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 64*1024 {
		return 0, errors.New("SSH bootstrap output exceeds 64 KiB")
	}
	return b.Buffer.Write(p)
}

func bootstrapMosh(ctx context.Context, ssh, host, server string, port int, command []string) (moshSession, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// No local shell; remote arguments are individually quoted. -T overrides a
	// RequestTTY setting, and -n keeps bootstrap from consuming terminal input.
	cmd := exec.CommandContext(ctx, ssh, "-n", "-T", "--", host, moshServerCommand(server, port, command))
	cmd.WaitDelay = 3 * time.Second
	var output, stderr boundedMoshOutput
	cmd.Stdout, cmd.Stderr = &output, &stderr
	defer func() { clear(output.Bytes()); clear(stderr.Bytes()) }()
	withDiagnostic := func(err error) error {
		if diagnostic := moshDiagnostic(stderr.String()); diagnostic != "" {
			return fmt.Errorf("%w\n%s", err, diagnostic)
		}
		return err
	}
	if err := cmd.Run(); err != nil {
		return moshSession{}, withDiagnostic(fmt.Errorf("SSH bootstrap failed: %w", err))
	}
	session, err := parseMoshConnect(output.String(), port)
	if err != nil {
		return moshSession{}, withDiagnostic(err)
	}
	return session, nil
}

func moshEnvironment(env []string, key string) []string {
	out := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, "MOSH_KEY=") {
			out = append(out, entry)
		}
	}
	return append(out, "MOSH_KEY="+key)
}

func mosh(parent context.Context, s config.Store, args []string) error {
	f := flags("mosh")
	host := f.String("ssh-host", "", "SSH destination/alias (defaults to peer name)")
	serverPort := f.Int("server-port", 0, "optional fixed remote port; default lets mosh-server choose")
	tunnelPort := f.Int("tunnel-port", 0, "published tunnel port (defaults to the port reported by mosh-server)")
	localPort := f.Int("local-port", 0, "local loopback UDP port; zero selects a free port")
	server := f.String("mosh-server", "", "remote executable path (default: discover via PATH or Homebrew)")
	if err := f.Parse(args); err != nil {
		return err
	}
	args = f.Args()
	if len(args) == 0 {
		return errors.New("mosh requires a qcat peer name")
	}
	peerName, command := args[0], args[1:]
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if *host == "" {
		*host = peerName
	}
	if strings.HasPrefix(*host, "-") || strings.ContainsAny(*host, "\x00\r\n") || strings.ContainsRune(*server, 0) {
		return errors.New("invalid SSH destination or mosh-server path")
	}
	if *serverPort < 0 || *serverPort > 65535 || *tunnelPort < 0 || *tunnelPort > 65535 || *localPort < 0 || *localPort > 65535 {
		return errors.New("ports must be 1–65535, or zero for automatic selection")
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return err
	}
	moshClient, err := exec.LookPath("mosh-client")
	if err != nil {
		return err
	}
	p, err := s.Peer(peerName)
	if err != nil {
		return err
	}
	if p.Endpoint == "" {
		return errors.New("peer has no endpoint; pair its serve --export descriptor")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: *localPort})
	if err != nil {
		return err
	}
	defer local.Close()
	port := local.LocalAddr().(*net.UDPAddr).Port
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
	if _, err = c.Ping(ctx); err != nil {
		return err
	}
	closeControl, err := control.StartPeer(ctx, s.Dir, fmt.Sprintf("mosh-%d-%s", port, peerName), peerName, func() any { return c.Status() }, cancel)
	if err != nil {
		return err
	}
	defer closeControl()
	renewDone, forwardDone := make(chan struct{}), make(chan error, 1)
	go func() {
		defer close(renewDone)
		transport.Maintain(ctx, c, func(err error) { fmt.Fprintln(os.Stderr, "qcat: tunnel recovery/renewal failed; retrying:", err) })
	}()
	defer func() { cancel(); <-renewDone }()
	session, err := bootstrapMosh(ctx, ssh, *host, *server, *serverPort, command)
	if err != nil {
		return err
	}
	if *tunnelPort == 0 {
		*tunnelPort = session.port
	}
	go func() {
		err := proxy.ForwardUDP(ctx, local, func(ctx context.Context) (net.Conn, error) {
			conn, err := c.DialUDPPort(ctx, uint16(*tunnelPort))
			if err != nil {
				return nil, err
			}
			return proxy.FramedUDP(conn), nil
		}, proxy.DefaultUDPIdleTimeout)
		forwardDone <- err
		cancel()
	}()
	defer func() { cancel(); <-forwardDone }()
	fmt.Fprintf(os.Stderr, "Mosh via %s: 127.0.0.1:%d -> tunnel %d -> server loopback:%d\n", peerName, port, *tunnelPort, session.port)
	cmd := exec.CommandContext(ctx, moshClient, "127.0.0.1", strconv.Itoa(port))
	cmd.Env = moshEnvironment(os.Environ(), session.key)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Give mosh-client time to restore terminal settings on qcat down/SIGTERM.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second
	return cmd.Run()
}
