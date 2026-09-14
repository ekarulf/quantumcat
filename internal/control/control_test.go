package control

import (
	"context"
	"os"
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
	close, err := Start(ctx, dir, "up-test", func() any { return map[string]string{"state": "ready"} }, cancel)
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
