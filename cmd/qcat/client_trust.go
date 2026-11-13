package main

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/ekarulf/quantumcat/internal/config"
	"github.com/tailscale/tailcat"
)

// guardClientTrust is shared by connect, forward, socks, up and mosh. Keep the
// startup identity pinned: replacing a name never adopts a new trust anchor.
func guardClientTrust(ctx context.Context, cancel context.CancelFunc, c *tailcat.Client, store config.Store, name string, pinned []byte) {
	check := func() error {
		peer, err := store.Peer(name)
		if err != nil || !bytes.Equal(peer.PublicKey, pinned) {
			cancel()
			return errors.New("paired server removed, replaced, or unreadable")
		}
		return nil
	}
	bootstrap := c.Bootstrap
	c.Bootstrap = func(ctx context.Context, send func([]byte) error, recv <-chan []byte) (tailcat.PresharedKey, error) {
		if err := check(); err != nil {
			return tailcat.PresharedKey{}, err
		}
		psk, err := bootstrap(ctx, func(b []byte) error {
			if err := check(); err != nil {
				return err
			}
			return send(b)
		}, recv)
		if trustErr := check(); trustErr != nil {
			clear(psk[:])
			return tailcat.PresharedKey{}, trustErr
		}
		return psk, err
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if check() != nil {
					return
				}
			}
		}
	}()
	// Also closes the device for modes whose application listener outlives ctx.
	context.AfterFunc(ctx, func() { c.Close() })
}
