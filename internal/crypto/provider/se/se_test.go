package se_test

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/ekarulf/quantumcat/internal/crypto/provider/se"
	"github.com/ekarulf/quantumcat/internal/crypto/provider/software"
	"github.com/ekarulf/quantumcat/internal/protocol"
)

func TestSecureEnclaveStandardLibraryInteroperability(t *testing.T) {
	enabled, configured := os.LookupEnv("QCAT_TEST_ENCLAVE")
	if !configured {
		enabled = os.Getenv("QCAT_TEST_SE")
	}
	if enabled != "1" {
		t.Skip("set QCAT_TEST_ENCLAVE=1 and QCAT_ENCLAVE_HELPER to exercise Apple hardware")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := se.Open()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := h.GenerateIdentity(ctx)
	if err != nil {
		h.Close()
		t.Fatal(err)
	}
	pub, err := h.PublicKey(ctx)
	h.Close()
	if err != nil {
		t.Fatal(err)
	}
	h, err = se.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err = h.LoadIdentity(ctx, ref); err != nil {
		t.Fatal(err)
	}
	clear(ref)
	si, err := software.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := si.PublicKey(ctx)
	var local, remote protocol.Keys
	rand.Read(local.WG[:])
	rand.Read(local.Disco[:])
	rand.Read(remote.WG[:])
	rand.Read(remote.Disco[:])
	server := &protocol.Server{Identity: si, Public: sp, Keys: remote, Authorized: func(yield func(protocol.PeerID, []byte) bool) { yield(protocol.ID(pub), pub) }}
	defer server.Close()
	c, hello, err := protocol.NewClient(ctx, h, se.NewKEM, sp, local, remote, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reply, _ := server.Handle(ctx, local.WG, hello, time.Now())
	if len(reply) == 0 {
		t.Fatal("Go crypto rejected Secure Enclave signature")
	}
	psk, finish, err := c.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	ack, session := server.Handle(ctx, local.WG, finish, time.Now())
	if session == nil || session.PSK != psk || !c.Accepted(ack) {
		t.Fatal("Apple/Go crypto KEM key confirmation failed")
	}
	session.Installed(true)

	// Exercise the Enclave as the server signer too. ServerHello signs the
	// complete 3,483-byte canonical transcript rather than its 48-byte digest.
	var clientKeys, serverKeys protocol.Keys
	rand.Read(clientKeys.WG[:])
	rand.Read(clientKeys.Disco[:])
	rand.Read(serverKeys.WG[:])
	rand.Read(serverKeys.Disco[:])
	enclaveServer := &protocol.Server{Identity: h, Public: pub, Keys: serverKeys, Authorized: func(yield func(protocol.PeerID, []byte) bool) { yield(protocol.ID(sp), sp) }}
	defer enclaveServer.Close()
	softwareClient, clientHello, err := protocol.NewClient(ctx, si, software.NewKEM, pub, clientKeys, serverKeys, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer softwareClient.Close()
	serverReply, _ := enclaveServer.Handle(ctx, clientKeys.WG, clientHello, time.Now())
	if len(serverReply) == 0 {
		t.Fatal("Secure Enclave failed to sign the canonical server transcript")
	}
	serverPSK, clientFinish, err := softwareClient.Complete(ctx, serverReply)
	if err != nil {
		t.Fatal("Go crypto rejected Secure Enclave server signature:", err)
	}
	serverAck, serverSession := enclaveServer.Handle(ctx, clientKeys.WG, clientFinish, time.Now())
	if serverSession == nil || serverSession.PSK != serverPSK || !softwareClient.Accepted(serverAck) {
		t.Fatal("Secure Enclave server key confirmation failed")
	}
	serverSession.Installed(true)
}
