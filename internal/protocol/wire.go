// Package protocol implements Quantumcat's version 1 authenticated PSK bootstrap.
package protocol

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

const (
	Version        = 1
	MaxPacket      = 32768
	ClientHello    = 1
	ServerHello    = 2
	ClientFinish   = 3
	ServerAccepted = 4
	helloSize      = 32*6 + 8 + mlkem1024.PublicKeySize
	serverSize     = 32*4 + mlkem1024.CiphertextSize + mldsa87.SignatureSize + 32
	ClientContext  = "qcat-handshake-client-v1"
	ServerContext  = "qcat-handshake-server-v1"
)

type PeerID [32]byte

func ID(pub []byte) PeerID { return sha256.Sum256(append([]byte("qcat-peer-v1"), pub...)) }
func (p PeerID) String() string {
	return "qpeer:" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(p[:])
}
func ParseID(s string) (PeerID, error) {
	var p PeerID
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimPrefix(s, "qpeer:"))
	if err != nil || len(b) != 32 {
		return p, errors.New("invalid PeerID")
	}
	copy(p[:], b)
	return p, nil
}

type Keys struct{ WG, Disco [32]byte }

func frame(kind byte, payload []byte) []byte {
	b := make([]byte, 8, 8+len(payload))
	copy(b, "QCAT")
	b[4] = Version
	b[5] = kind
	binary.BigEndian.PutUint16(b[6:], uint16(len(payload)))
	return append(b, payload...)
}
func Parse(b []byte) (byte, []byte, error) {
	if len(b) < 8 || len(b) > MaxPacket || string(b[:4]) != "QCAT" || b[4] != Version || int(binary.BigEndian.Uint16(b[6:8])) != len(b)-8 {
		return 0, nil, errors.New("invalid handshake frame")
	}
	sizes := map[byte]int{ClientHello: helloSize + mldsa87.SignatureSize, ServerHello: serverSize, ClientFinish: 64, ServerAccepted: 64}
	if n, ok := sizes[b[5]]; !ok || len(b)-8 != n {
		return 0, nil, errors.New("invalid handshake payload")
	}
	return b[5], b[8:], nil
}
func join(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
func verify(pub []byte, label string, msg, sig []byte) bool {
	if len(pub) != mldsa87.PublicKeySize || len(sig) != mldsa87.SignatureSize {
		return false
	}
	var p mldsa87.PublicKey
	return p.UnmarshalBinary(pub) == nil && mldsa87.Verify(&p, msg, []byte(label), sig)
}
func transcript(hello []byte, server PeerID, keys Keys, nonce, ct []byte) [32]byte {
	// hello: client ID, client WG, client disco, client nonce, server ID,
	// reserved zero bytes, timestamp, KEM key. All fields have fixed sizes.
	return sha256.Sum256(join([]byte("qcat-transcript-v1"), []byte{Version}, server[:], hello[:32],
		keys.WG[:], hello[32:64], keys.Disco[:], hello[64:96], hello[200:], ct, hello[96:128], nonce))
}
