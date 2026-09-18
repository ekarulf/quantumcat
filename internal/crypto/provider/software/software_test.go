package software

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"testing"
)

func TestIdentitySeedRoundTrip(t *testing.T) {
	ctx := context.Background()
	generated, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	seed := generated.Bytes()
	defer clear(seed)
	if len(seed) != mldsa.PrivateKeySize {
		t.Fatalf("private encoding is %d bytes, want %d", len(seed), mldsa.PrivateKeySize)
	}
	loaded, err := Load(seed)
	if err != nil {
		t.Fatal(err)
	}
	want, err := generated.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loaded.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("loaded identity changed public key")
	}
}
