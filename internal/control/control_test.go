package control

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestStatusAndShutdown(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "qcat-control-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	close, err := StartPeer(ctx, dir, "up-test", "test", func() any { return map[string]string{"state": "ready"} }, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	status, err := Query(dir, "test", "status")
	if err != nil || len(status) != 1 {
		t.Fatalf("status: %v %v", status, err)
	}
	if _, err = Query(dir, "test", "stop"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel process")
	}
}

func TestShutdownMatchesExplicitPeer(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "qcat-control-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	type runtime struct {
		name, peer string
		stopped    atomic.Bool
	}
	runtimes := []*runtime{
		{name: "forward-mini", peer: "mini"},
		{name: "forward-udp-60001-mini", peer: "mini"},
		{name: "forward-home-mini", peer: "home-mini"},
		{name: "forward-udp-60001-home-mini", peer: "home-mini"},
		{name: "serve"},
		{name: "forward-serve", peer: "serve"},
	}
	for _, rt := range runtimes {
		close, err := StartPeer(context.Background(), dir, rt.name, rt.peer, func() any { return "ready" }, func() { rt.stopped.Store(true) })
		if err != nil {
			t.Fatal(err)
		}
		defer close()
	}
	result, err := Query(dir, "mini", "stop")
	if err != nil || len(result) != 2 {
		t.Fatalf("mini: %v %v", result, err)
	}
	result, err = Query(dir, "serve", "stop")
	if err != nil || len(result) != 1 {
		t.Fatalf("serve: %v %v", result, err)
	}
	// Responses arrive after stop is invoked and the server closes the socket.
	for _, rt := range runtimes {
		want := rt.peer == "mini" || rt.name == "serve"
		if rt.stopped.Load() != want {
			t.Errorf("%s stopped=%v, want %v", rt.name, rt.stopped.Load(), want)
		}
	}
}
