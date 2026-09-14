package main

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ekarulf/quantumcat/internal/config"
	"github.com/ekarulf/quantumcat/internal/crypto/provider/software"
	"github.com/ekarulf/quantumcat/internal/protocol"
	"github.com/ekarulf/quantumcat/internal/proxy"
	"github.com/ekarulf/quantumcat/internal/transport"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

const testMoshKey = "ABCDEFGHIJKLMNOPQRSTUV"

func TestParseMoshConnect(t *testing.T) {
	good := "MOSH CONNECT 60001 " + testMoshKey
	for _, tc := range []struct {
		name, output string
		ok           bool
	}{
		{"plain", good + "\n", true},
		{"banner-crlf", "Welcome\r\n" + good + "\r\nserver detached\n", true},
		{"missing", "mosh-server: not found", false},
		{"duplicate", good + "\n" + good, false},
		{"wrong-port", "MOSH CONNECT 60002 " + testMoshKey, false},
		{"zero", "MOSH CONNECT 0 " + testMoshKey, false},
		{"overflow", "MOSH CONNECT 65536 " + testMoshKey, false},
		{"bad-key", "MOSH CONNECT 60001 malicious;$(command)", false},
		{"short-key", "MOSH CONNECT 60001 ABC", false},
		{"extra-field", good + " extra", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := parseMoshConnect(tc.output, 60001)
			if tc.ok {
				if err != nil || key.key != testMoshKey || key.port != 60001 {
					t.Fatalf("valid bootstrap rejected: %v", err)
				}
			} else if err == nil || key != (moshSession{}) {
				t.Fatal("invalid bootstrap accepted")
			}
			if err != nil && strings.Contains(err.Error(), testMoshKey) {
				t.Fatal("error leaked session key")
			}
		})
	}
}

func TestMoshRemoteQuoting(t *testing.T) {
	words := []string{"", "two words", "it's quoted", "$(exit 17)", "; exit 18", "line\nbreak"}
	quoted := make([]string, len(words))
	for i, word := range words {
		quoted[i] = shellWord(word)
	}
	out, err := exec.Command("/bin/sh", "-c", "printf '%s\\000' "+strings.Join(quoted, " ")).Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != strings.Join(words, "\x00")+"\x00" {
		t.Fatal("shell quoting changed arguments")
	}
	command := moshServerCommand("/path with spaces/mosh-server", 60001, words)
	if !strings.HasPrefix(command, "'/path with spaces/mosh-server' 'new' '-i' '127.0.0.1' '-p' '60001'") {
		t.Fatal("remote bootstrap does not bind the requested loopback port")
	}
	if strings.Contains(moshServerCommand("mosh-server", 0, nil), "'-p'") {
		t.Fatal("automatic mode must leave remote port selection to mosh-server")
	}
}

func TestMoshServerDiscoveryPreservesArguments(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "mosh-server")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\000' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	args := []string{"tmux", "two words", "it's quoted", "$(exit 42)"}
	cmd := exec.Command("/bin/sh", "-c", moshServerCommand("", 0, args))
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{"new", "-i", "127.0.0.1", "-c", "256", "-l", "LANG=en_US.UTF-8", "--"}, args...)
	if string(out) != strings.Join(want, "\x00")+"\x00" {
		t.Fatal("discovery changed remote arguments or added a fixed port")
	}
}

func fakeMoshSSH(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMoshBootstrap(t *testing.T) {
	ssh := fakeMoshSSH(t, `[ "$1" = -n ] && [ "$2" = -T ] && [ "$3" = -- ] && [ "$4" = mini-qcat ] || exit 42
printf 'banner\nMOSH CONNECT 60001 ABCDEFGHIJKLMNOPQRSTUV\n'
`)
	key, err := bootstrapMosh(context.Background(), ssh, "mini-qcat", "mosh-server", 60001, nil)
	if err != nil || key.key != testMoshKey || key.port != 60001 {
		t.Fatalf("bootstrap failed: %v", err)
	}
}

func TestMoshBootstrapFailureDoesNotLeakKey(t *testing.T) {
	ssh := fakeMoshSSH(t, "printf 'MOSH CONNECT 60001 "+testMoshKey+"\\nPermission denied (publickey).\\nkey="+testMoshKey+"\\n' >&2\nexit 255\n")
	key, err := bootstrapMosh(context.Background(), ssh, "mini", "mosh-server", 60001, nil)
	if err == nil || key != (moshSession{}) || strings.Contains(err.Error(), testMoshKey) {
		t.Fatal("failed SSH bootstrap accepted or leaked key")
	}
	if !strings.Contains(err.Error(), "Permission denied (publickey).") {
		t.Fatal("SSH diagnostic was hidden")
	}
}

func TestMoshDiagnosticBoundAndControlCharacters(t *testing.T) {
	d := moshDiagnostic("\x1b[31merror\r\nMOSH CONNECT 60001 " + testMoshKey + "\n" + strings.Repeat("x ", 5000))
	if strings.ContainsAny(d, "\x1b\r") || strings.Contains(d, testMoshKey) || len(d) > 4120 {
		t.Fatal("unsafe or unbounded diagnostic")
	}
}

func TestMoshBootstrapCancellation(t *testing.T) {
	ssh := fakeMoshSSH(t, "exec sleep 30\n")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := bootstrapMosh(ctx, ssh, "mini", "mosh-server", 60001, nil); err == nil {
		t.Fatal("canceled bootstrap succeeded")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("bootstrap did not stop promptly")
	}
}

func TestMoshOutputBoundAndEnvironment(t *testing.T) {
	var b boundedMoshOutput
	if _, err := b.Write(make([]byte, 65536)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("x")); err == nil || b.Len() != 65536 {
		t.Fatal("bootstrap output unbounded")
	}
	env := moshEnvironment([]string{"TERM=xterm", "MOSH_KEY=old", "MOSH_KEY=older", "MOSH_PREDICTION_DISPLAY=adaptive"}, testMoshKey)
	if strings.Join(env, "\n") != "TERM=xterm\nMOSH_PREDICTION_DISPLAY=adaptive\nMOSH_KEY="+testMoshKey {
		t.Fatal("session key not replaced or environment lost")
	}
}

func TestMoshRejectsBadOptionsBeforeLoadingIdentity(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--local-port", "-1", "mini"}, {"--server-port", "-1", "mini"},
		{"--tunnel-port", "65536", "mini"}, {"--ssh-host", "-oProxyCommand=bad", "mini"},
	} {
		if err := run(context.Background(), append([]string{"--config", t.TempDir(), "mosh"}, args...)); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

// Substitute only SSH and mosh-client; exercise the real authenticated tunnel,
// framing, port mapping, ephemeral local binding, and teardown end to end.
func TestMoshSessionWithMockExecutables(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	relay := derpserver.New(key.NewNode(), t.Logf)
	httpRelay := httptest.NewTLSServer(derpserver.Handler(relay))
	defer httpRelay.Close()
	defer relay.Close()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		var b [512]byte
		for {
			n, addr, err := echo.ReadFromUDP(b[:])
			if err != nil {
				return
			}
			echo.WriteToUDP(b[:n], addr)
		}
	}()
	defer func() { echo.Close(); <-echoDone }()
	// macOS Unix socket paths are limited to 104 bytes; testing.TempDir's
	// per-test prefix alone can exceed that before the runtime name is added.
	configDir, err := os.MkdirTemp("/tmp", "qcat-mosh-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(configDir) })
	s := config.Store{Dir: configDir}
	if err := s.Init(ctx, "client", "software"); err != nil {
		t.Fatal(err)
	}
	ci, _, _, closeIdentity, err := s.Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIdentity()
	cp, err := ci.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	si, _ := software.Generate()
	sp, _ := si.PublicKey(ctx)
	server := transport.Server(si, sp, key.NewNode(), func(id protocol.PeerID) []byte {
		if id == protocol.ID(cp) {
			return cp
		}
		return nil
	})
	server.Region = &tailcfg.DERPRegion{RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{Name: "test", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: httpRelay.Listener.Addr().(*net.TCPAddr).Port, STUNPort: -1, InsecureForTests: true}}}
	remotePort := echo.LocalAddr().(*net.UDPAddr).Port
	server.OnUDP, err = proxy.UDPServices(ctx, map[uint16]string{uint16(remotePort): echo.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	server.ServedUDPPorts = []filter.PortRange{{First: uint16(remotePort), Last: uint16(remotePort)}}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	p := config.Peer{Version: 1, Name: "mini", PeerID: protocol.ID(sp).String(), PublicKey: sp, Endpoint: server.TailcatAddr()}
	if err := config.WriteNew(filepath.Join(s.Dir, "peers", "mini.qpeer"), p); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	sshBody := fmt.Sprintf("#!/bin/sh\ncase \"$5\" in *\"'-p'\"*) exit 43;; esac\nprintf 'MOSH CONNECT %d %s\\n'\n", remotePort, testMoshKey)
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(sshBody), 0700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := "#!/bin/sh\nexec " + shellWord(exe) + " -test.run=^TestMoshClientProcess$ -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "mosh-client"), []byte(helper), 0700); err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(bin, "bound-address")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("QCAT_MOSH_TEST_RESULT", resultPath)
	if err := mosh(ctx, s, []string{"mini"}); err != nil {
		t.Fatal(err)
	}
	bound, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := net.ResolveUDPAddr("udp4", string(bound))
	if err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("forwarder retained local socket after mosh-client exited: %v", err)
	}
	rebound.Close()
}

func TestMoshClientProcess(t *testing.T) {
	result := os.Getenv("QCAT_MOSH_TEST_RESULT")
	if result == "" {
		return
	}
	if os.Getenv("MOSH_KEY") != testMoshKey {
		t.Fatal("missing session key environment")
	}
	args := os.Args[len(os.Args)-2:]
	if args[0] != "127.0.0.1" {
		t.Fatal("client not bound to loopback")
	}
	addr := net.JoinHostPort(args[0], args[1])
	conn, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 8; i++ {
		conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte("mosh-wrapper-test")); err != nil {
			t.Fatal(err)
		}
		var b [128]byte
		n, err := conn.Read(b[:])
		if err != nil {
			continue
		} // UDP loss while first handshake completes is fine.
		if string(b[:n]) != "mosh-wrapper-test" {
			t.Fatal("UDP payload changed")
		}
		if err := os.WriteFile(result, []byte(addr), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("forwarded UDP did not recover within eight attempts")
}
