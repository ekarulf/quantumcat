package main

import (
	"testing"

	"tailscale.com/net/portmapper/portmappertype"
)

func TestPortMapperRegistered(t *testing.T) {
	if _, ok := portmappertype.HookNewPortMapper.GetOk(); !ok {
		t.Fatal("Tailscale portmapper feature is not registered")
	}
}
