package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ekarulf/quantumcat/internal/config"
	"github.com/ekarulf/quantumcat/internal/crypto/provider/software"
	"github.com/ekarulf/quantumcat/internal/protocol"
	"github.com/tailscale/tailcat"
)

func TestClientTrustRemovalAndReplacement(t *testing.T) {
	for _, mutation := range []string{"remove", "replace"} {
		t.Run(mutation, func(t *testing.T) {
			store := config.Store{Dir: t.TempDir()}
			identity, err := software.Generate()
			if err != nil {
				t.Fatal(err)
			}
			defer identity.Destroy()
			pub, _ := identity.PublicKey(context.Background())
			path := filepath.Join(store.Dir, "peers", "server.qpeer")
			peer := config.Peer{Version: config.PeerVersion, Name: "server", PublicKey: pub, PeerID: protocol.ID(pub).String()}
			if err := config.WriteNew(path, peer); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			c := &tailcat.Client{Bootstrap: func(context.Context, func([]byte) error, <-chan []byte) (tailcat.PresharedKey, error) {
				close(entered)
				<-release
				return tailcat.PresharedKey{1}, nil
			}}
			guardClientTrust(ctx, cancel, c, store, "server", pub)
			done := make(chan tailcat.PresharedKey, 1)
			go func() { psk, _ := c.Bootstrap(ctx, nil, nil); done <- psk }()
			<-entered
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if mutation == "replace" {
				other, _ := software.Generate()
				defer other.Destroy()
				peer.PublicKey, _ = other.PublicKey(ctx)
				peer.PeerID = protocol.ID(peer.PublicKey).String()
				if err := config.WriteNew(path, peer); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("active client not cancelled")
			}
			close(release)
			if psk := <-done; !psk.IsZero() {
				t.Fatal("in-flight renewal returned revoked PSK")
			}
			if psk, err := c.Bootstrap(ctx, nil, nil); err == nil || !psk.IsZero() {
				t.Fatal("revoked client renewed")
			}
		})
	}
}
