package se

import (
	"bytes"
	"context"
	"errors"
	"sync"
)

// Identity reloads the same opaque Enclave reference after helper failure.
// It deliberately does not expose Helper.Done: a failed subprocess is not a
// dead identity, and restarting it must not tear down established tunnels.
type Identity struct {
	mu          sync.Mutex
	helper      *Helper
	ref, public []byte
	open        func() (*Helper, error)
	closed      bool
}

func OpenIdentity(ctx context.Context, ref []byte) (*Identity, error) {
	return openIdentity(ctx, ref, Open)
}

func openIdentity(ctx context.Context, ref []byte, open func() (*Helper, error)) (*Identity, error) {
	i := &Identity{ref: append([]byte(nil), ref...), open: open}
	if err := i.load(ctx); err != nil {
		i.Close()
		return nil, err
	}
	return i, nil
}

func (i *Identity) load(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h, err := i.open()
	if err != nil {
		return err
	}
	if err = h.LoadIdentity(ctx, i.ref); err != nil {
		h.Close()
		return err
	}
	pub, err := h.PublicKey(ctx)
	if err != nil {
		h.Close()
		return err
	}
	if i.public != nil && !bytes.Equal(i.public, pub) {
		h.Close()
		return errors.New("reloaded Enclave identity public key changed")
	}
	i.public = append(i.public[:0], pub...)
	i.helper = h
	return nil
}

func (i *Identity) PublicKey(ctx context.Context) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil, errors.New("Enclave identity closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]byte(nil), i.public...), nil
}

func (i *Identity) Sign(ctx context.Context, label string, msg []byte) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil, errors.New("Enclave identity closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if i.helper != nil {
		select {
		case <-i.helper.Done():
			i.helper.Close()
			i.helper = nil
		default:
		}
	}
	if i.helper == nil {
		if err := i.load(ctx); err != nil {
			return nil, err
		}
	}
	sig, err := i.helper.Sign(ctx, label, msg)
	if err != nil {
		// Never reuse a possibly desynchronized pipe. The next operation reloads
		// the identity in a fresh helper; ephemeral KEM helpers are never revived.
		i.helper.Close()
		i.helper = nil
	}
	return sig, err
}

func (i *Identity) Close() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.closed = true
	if i.helper != nil {
		i.helper.Close()
		i.helper = nil
	}
	clear(i.ref)
	i.ref = nil
}
