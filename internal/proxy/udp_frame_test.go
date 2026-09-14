package proxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
)

type frameCapture struct {
	net.Conn
	frames [][]byte
}

func (c *frameCapture) Write(b []byte) (int, error) {
	c.frames = append(c.frames, append([]byte(nil), b...))
	return len(b), nil
}

func TestUDPFramesReorderAndBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, udpChunkSize, udpChunkSize + 1, 1200, 1220, 1221, 1280, 8192, MaxUDPDatagram} {
		capture := new(frameCapture)
		conn := FramedUDP(capture)
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if n, err := conn.Write(payload); err != nil || n != size {
			t.Fatalf("size %d: %d %v", size, n, err)
		}
		decoder := new(udpDecoder)
		now := time.Now()
		for i := len(capture.frames) - 1; i >= 0; i-- {
			frame := capture.frames[i]
			if len(frame) > tailcat.MaxUDPPayload {
				t.Fatal("frame exceeds tunnel MTU")
			}
			paddedInner := (len(frame) + 40 + 8 + 15) &^ 15
			for _, outerIPHeader := range []int{20, 40} {
				if outerIPHeader+8+32+paddedInner > 1200 {
					t.Fatal("encrypted IP packet exceeds 1200 bytes")
				}
			}
			got, complete := decoder.accept(frame, now)
			if i > 0 {
				if complete {
					t.Fatal("partial datagram delivered")
				}
				if _, complete = decoder.accept(frame, now); complete {
					t.Fatal("duplicate fragment completed datagram")
				}
			} else if !complete || !bytes.Equal(got, payload) {
				t.Fatalf("reassembly failed at size %d", size)
			}
		}
		if len(decoder.pending) != 0 {
			t.Fatal("completed reassembly retained")
		}
	}
	capture := new(frameCapture)
	if _, err := FramedUDP(capture).Write(make([]byte, MaxUDPDatagram+1)); err == nil || len(capture.frames) != 0 {
		t.Fatal("oversize datagram emitted frames")
	}
}

func TestUDPFramesLossExpiryAndLimits(t *testing.T) {
	capture := new(frameCapture)
	conn := FramedUDP(capture)
	for i := 0; i < udpMaxAssemblies+4; i++ {
		conn.Write(make([]byte, udpChunkSize+1))
	}
	decoder := new(udpDecoder)
	now := time.Now()
	for i := 0; i < len(capture.frames); i += 2 {
		if _, ok := decoder.accept(capture.frames[i], now); ok {
			t.Fatal("incomplete datagram delivered")
		}
		if len(decoder.pending) > udpMaxAssemblies {
			t.Fatal("unbounded reassembly")
		}
	}
	decoder.accept(nil, now.Add(udpAssemblyLifetime))
	if len(decoder.pending) != 0 {
		t.Fatal("expired reassemblies retained")
	}
	for _, kind := range []string{"magic", "oversize", "index", "short", "trailing"} {
		b := append([]byte(nil), capture.frames[0]...)
		switch kind {
		case "magic":
			b[0] ^= 1
		case "oversize":
			binary.BigEndian.PutUint16(b[12:14], 65535)
		case "index":
			binary.BigEndian.PutUint16(b[14:16], 65535)
		case "short":
			b = b[:len(b)-1]
		case "trailing":
			b = append(b, 0)
		}
		if _, ok := decoder.accept(b, now); ok || len(decoder.pending) != 0 {
			t.Fatalf("accepted malformed %s", kind)
		}
	}
}

func TestSparseFragmentsAllocateOnlyReceivedPayload(t *testing.T) {
	capture := new(frameCapture)
	if _, err := FramedUDP(capture).Write(make([]byte, MaxUDPDatagram)); err != nil {
		t.Fatal(err)
	}
	decoder := new(udpDecoder)
	decoder.accept(capture.frames[0], time.Now())
	retained := 0
	for _, assembly := range decoder.pending {
		for _, chunk := range assembly.chunks {
			retained += cap(chunk)
		}
	}
	if retained > 2*udpChunkSize {
		t.Fatalf("one fragment reserved %d bytes", retained)
	}
}
func FuzzUDPFrame(f *testing.F) {
	f.Add([]byte("QUD1"))
	c := new(frameCapture)
	FramedUDP(c).Write([]byte("mosh"))
	f.Add(c.frames[0])
	f.Fuzz(func(t *testing.T, b []byte) { d := new(udpDecoder); d.accept(b, time.Unix(0, 0)) })
}
