package main

import "testing"

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
