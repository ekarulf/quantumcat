package software

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/ekarulf/quantumcat/internal/crypto/provider"
)

type Identity struct{ key *mldsa87.PrivateKey }

func Generate() (*Identity, error) {
	_, key, err := mldsa87.GenerateKey(rand.Reader)
	return &Identity{key}, err
}
func Load(raw []byte) (*Identity, error) {
	key := new(mldsa87.PrivateKey)
	if err := key.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	return &Identity{key}, nil
}
func (i *Identity) Bytes() []byte { return i.key.Bytes() }
func (i *Identity) Destroy() {
	if i.key != nil {
		*i.key = mldsa87.PrivateKey{}
		i.key = nil
	}
}
func (i *Identity) PublicKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return i.key.Public().(*mldsa87.PublicKey).Bytes(), nil
}
func (i *Identity) Sign(ctx context.Context, label string, msg []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sig := make([]byte, mldsa87.SignatureSize)
	err := mldsa87.SignTo(i.key, msg, []byte(label), true, sig)
	return sig, err
}

type KEM struct {
	mu     sync.Mutex
	key    *mlkem1024.PrivateKey
	public []byte
}

func NewKEM(ctx context.Context) (provider.KEM, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pub, key, err := mlkem1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}
	raw, err := pub.MarshalBinary()
	return &KEM{key: key, public: raw}, err
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
	if len(ct) != mlkem1024.CiphertextSize {
		return nil, errors.New("invalid ciphertext length")
	}
	ss := make([]byte, mlkem1024.SharedKeySize)
	k.key.DecapsulateTo(ss, ct)
	return ss, nil
}
func (k *KEM) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key != nil {
		*k.key = mlkem1024.PrivateKey{}
		k.key = nil
	}
}
