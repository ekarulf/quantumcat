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

func TestSecureEnclaveCIRCLInteroperability(t *testing.T) {
	if os.Getenv("QCAT_TEST_SE") != "1" {
		t.Skip("set QCAT_TEST_SE=1 and QCAT_SE_HELPER to exercise Apple hardware")
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
	server := &protocol.Server{Identity: si, Public: sp, Keys: remote, Lookup: func(id protocol.PeerID) []byte {
		if id == protocol.ID(pub) {
			return pub
		}
		return nil
	}}
	defer server.Close()
	c, hello, err := protocol.NewClient(ctx, h, se.NewKEM, sp, local, remote, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reply, _ := server.Handle(ctx, local.WG, hello, time.Now())
	if len(reply) == 0 {
		t.Fatal("CIRCL rejected Secure Enclave signature")
	}
	psk, finish, err := c.Complete(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	ack, session := server.Handle(ctx, local.WG, finish, time.Now())
	if session == nil || session.PSK != psk || !c.Accepted(ack) {
		t.Fatal("Apple/CIRCL KEM key confirmation failed")
	}
}
