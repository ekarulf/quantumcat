// Package provider defines the narrow private-key boundary used by the protocol.
package provider

import "context"

type Identity interface {
	PublicKey(context.Context) ([]byte, error)
	Sign(context.Context, string, []byte) ([]byte, error)
}

// KEM represents one connection's key. Destroy must be called on every path.
type KEM interface {
	PublicKey(context.Context) ([]byte, error)
	Decapsulate(context.Context, []byte) ([]byte, error)
	Destroy()
}

type NewKEM func(context.Context) (KEM, error)
