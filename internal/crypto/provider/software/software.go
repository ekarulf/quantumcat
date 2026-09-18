package software

import (
	"context"
	"crypto/mldsa"
	"crypto/mlkem"
	"errors"
	"sync"

	"github.com/ekarulf/quantumcat/internal/crypto/provider"
)

type Identity struct{ key *mldsa.PrivateKey }

func Generate() (*Identity, error) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA87())
	return &Identity{key}, err
}
func Load(raw []byte) (*Identity, error) {
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), raw)
	if err != nil {
		return nil, err
	}
	return &Identity{key}, nil
}
func (i *Identity) Bytes() []byte { return i.key.Bytes() }
func (i *Identity) Destroy() {
	i.key = nil
}
func (i *Identity) PublicKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if i.key == nil {
		return nil, errors.New("identity destroyed")
	}
	return i.key.PublicKey().Bytes(), nil
}
func (i *Identity) Sign(ctx context.Context, label string, msg []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if i.key == nil {
		return nil, errors.New("identity destroyed")
	}
	return i.key.Sign(nil, msg, &mldsa.Options{Context: label})
}

type KEM struct {
	mu     sync.Mutex
	key    *mlkem.DecapsulationKey1024
	public []byte
}

func NewKEM(ctx context.Context) (provider.KEM, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	return &KEM{key: key, public: key.EncapsulationKey().Bytes()}, nil
}
func (k *KEM) PublicKey(ctx context.Context) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key == nil {
		return nil, errors.New("KEM destroyed")
	}
	return append([]byte(nil), k.public...), ctx.Err()
}
func (k *KEM) Decapsulate(ctx context.Context, ct []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if k.key == nil {
		return nil, errors.New("KEM destroyed")
	}
	return k.key.Decapsulate(ct)
}
func (k *KEM) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.key = nil
}
