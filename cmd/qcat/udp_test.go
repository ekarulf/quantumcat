package main

import (
	"context"
	"fmt"
	"github.com/ekarulf/quantumcat/internal/config"
	"strings"
	"testing"
)

func TestUDPForwardSpec(t *testing.T) {
	for _, spec := range []string{"60001:60001", "0:65535", "1:1"} {
		local, port, err := udpForwardSpec(spec)
		if err != nil || local == "" || port == 0 {
			t.Fatalf("%s: %s %d %v", spec, local, port, err)
		}
	}
	for _, spec := range []string{"", "60001", "60001:localhost:60001", "-1:60001", "65536:1", "1:0", "1:65536", "1:abc"} {
		if _, _, err := udpForwardSpec(spec); err == nil {
			t.Fatalf("accepted %q", spec)
		}
	}
}
func TestUDPServiceSpecs(t *testing.T) {
	targets, err := udpServiceSpecs([]string{"60001=127.0.0.1:60001", "60002=[::1]:60002"})
	if err != nil || len(targets) != 2 {
		t.Fatalf("%v %v", targets, err)
	}
	for _, entries := range [][]string{{"0=localhost:1"}, {"65536=localhost:1"}, {"1=localhost:0"}, {"1=localhost"}, {"1=localhost:2", "1=localhost:3"}} {
		if _, err := udpServiceSpecs(entries); err == nil {
			t.Fatalf("accepted %q", entries)
		}
	}
}

func TestUDPServiceRanges(t *testing.T) {
	targets, err := udpServiceSpecs([]string{"60000:61000=127.0.0.1:60000"})
	if err != nil || len(targets) != 1001 {
		t.Fatalf("range expansion: count=%d err=%v", len(targets), err)
	}
	for port := 60000; port <= 61000; port++ {
		if targets[uint16(port)] != fmt.Sprintf("127.0.0.1:%d", port) {
			t.Fatalf("wrong mapping for %d", port)
		}
	}
	if _, ok := targets[59999]; ok {
		t.Fatal("published below range")
	}
	if _, ok := targets[61001]; ok {
		t.Fatal("published above range")
	}
	targets, err = udpServiceSpecs([]string{"65534:65535=[::1]:1234"})
	if err != nil || len(targets) != 2 || targets[65534] != "[::1]:1234" || targets[65535] != "[::1]:1235" {
		t.Fatalf("offset/IPv6/end-boundary range failed: %v", err)
	}
	for _, entries := range [][]string{
		{"0:1=localhost:1"}, {"2:1=localhost:1"}, {"1:65536=localhost:1"},
		{"1:=localhost:1"}, {":2=localhost:1"}, {"1:2:3=localhost:1"},
		{"1:2=localhost:65535"}, {"1:2=localhost:0"}, {"1:2=localhost"},
		{"60000:61000=localhost:60000", "60001=localhost:60001"},
		{"1:3=localhost:1", "3:5=localhost:10"},
	} {
		if _, err := udpServiceSpecs(entries); err == nil {
			t.Fatalf("accepted invalid ranges %v", entries)
		}
	}
}

func TestDuplicateTCPServiceRejectedBeforeIdentityLoad(t *testing.T) {
	err := serve(context.Background(), config.Store{Dir: t.TempDir()}, []string{
		"--tcp", "22=127.0.0.1:2222", "--tcp", "22=127.0.0.1:22",
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate TCP service port") {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
}
