// Package protocol implements Quantumcat's version 1 authenticated PSK bootstrap.
package protocol

import (
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	Version          = 1
	MaxPacket        = 32768
	ClientHello      = 1
	ServerHello      = 2
	ClientFinish     = 3
	ServerAccepted   = 4
	hashSize         = sha512.Size384
	proofSize        = sha512.Size384
	helloSize        = 32*6 + 8 + mlkem.EncapsulationKeySize1024
	serverSize       = 32*4 + mlkem.CiphertextSize1024 + mldsa.MLDSA87SignatureSize + proofSize
	transcriptSize   = len(transcriptDomain) + 1 + 32*4 + mlkem.CiphertextSize1024 + helloSize
	ClientContext    = "qcat-handshake-client-v1"
	ServerContext    = "qcat-handshake-server-v1"
	peerIDDomain     = "qcat-peer-v1" // Frozen independently of Version.
	transcriptDomain = "qcat-transcript-v1"
)

type PeerID [32]byte

func ID(pub []byte) PeerID {
	return sha512.Sum512_256(append([]byte(peerIDDomain), pub...))
}
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
	if !ValidFrame(b) {
		return 0, nil, errors.New("invalid handshake frame")
	}
	return b[5], b[8:], nil
}

// ValidFrame performs the allocation-free framing checks that are safe to run
// before a packet enters the bounded bootstrap queue.
func ValidFrame(b []byte) bool {
	if len(b) < 8 || len(b) > MaxPacket || string(b[:4]) != "QCAT" || b[4] != Version || int(binary.BigEndian.Uint16(b[6:8])) != len(b)-8 {
		return false
	}
	var size int
	switch b[5] {
	case ClientHello:
		size = helloSize + mldsa.MLDSA87SignatureSize
	case ServerHello:
		size = serverSize
	case ClientFinish, ServerAccepted:
		size = hashSize + proofSize
	default:
		return false
	}
	return len(b)-8 == size
}
func join(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
func verify(pub []byte, label string, msg, sig []byte) bool {
	if len(pub) != mldsa.MLDSA87PublicKeySize || len(sig) != mldsa.MLDSA87SignatureSize {
		return false
	}
	p, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pub)
	return err == nil && mldsa.Verify(p, msg, sig, &mldsa.Options{Context: label}) == nil
}

// transcript returns the canonical transcript bytes and their SHA-384 digest.
// Both come from one function so the signature and key schedule cannot drift:
// the server signs the bytes, while confirmation and session state use the
// digest.
func transcript(hello []byte, server PeerID, keys Keys, nonce, ct []byte) ([]byte, [hashSize]byte) {
	// Cover the complete signed hello so future fields cannot be authenticated
	// by the client yet omitted from the server's attestation and key schedule.
	b := join([]byte(transcriptDomain), []byte{Version}, server[:],
		keys.WG[:], keys.Disco[:], nonce, ct, hello)
	return b, sha512.Sum384(b)
}
