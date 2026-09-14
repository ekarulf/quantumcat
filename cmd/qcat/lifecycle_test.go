package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClientHasNoArtificialSessionDeadline(t *testing.T) {
	ctx, cancel := clientContext(context.Background())
	defer cancel()
	if deadline, ok := ctx.Deadline(); ok {
		t.Fatalf("SSH session has artificial deadline: %v", deadline)
	}
	parent, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	child, close := clientContext(parent)
	defer close()
	select {
	case <-child.Done():
		if !errors.Is(child.Err(), context.DeadlineExceeded) {
			t.Fatal(child.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("client lease ignored earlier deadline")
	}
}
