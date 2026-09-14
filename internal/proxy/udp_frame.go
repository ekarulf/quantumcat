package proxy

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tailscale/tailcat"
)

const (
	// UDPWirePacketLimit budgets a complete direct-path IPv6 packet, including
	// outer IPv6 (40), UDP (8), WireGuard header/tag (32), inner IPv6/UDP (48),
	// and WireGuard's 16-byte padding alignment. IPv4 outer packets are smaller.
	UDPWirePacketLimit  = 1200
	udpFrameHeader      = 16
	udpInnerIPLimit     = (UDPWirePacketLimit - 40 - 8 - 32) &^ 15
	udpFrameLimit       = min(tailcat.MaxUDPPayload, udpInnerIPLimit-48)
	udpChunkSize        = udpFrameLimit - udpFrameHeader
	udpMaxAssemblies    = 8
	udpAssemblyLifetime = 2 * time.Second
)

type udpAssembly struct {
	chunks    [64][]byte
	size      int
	seen      uint64 // at most 63 fragments for an IPv4 UDP payload
	remaining int
	expires   time.Time
}
type udpDecoder struct{ pending map[uint64]*udpAssembly }

// accept validates sizes before allocation and bounds incomplete datagrams.
func (d *udpDecoder) accept(frame []byte, now time.Time) ([]byte, bool) {
	for id, p := range d.pending {
		if !now.Before(p.expires) {
			delete(d.pending, id)
		}
	}
	if len(frame) < udpFrameHeader || len(frame) > udpFrameLimit || string(frame[:4]) != "QUD1" {
		return nil, false
	}
	id := binary.BigEndian.Uint64(frame[4:12])
	size := int(binary.BigEndian.Uint16(frame[12:14]))
	index := int(binary.BigEndian.Uint16(frame[14:16]))
	if size > MaxUDPDatagram {
		return nil, false
	}
	count := (size + udpChunkSize - 1) / udpChunkSize
	if count == 0 {
		count = 1
	}
	if index >= count {
		return nil, false
	}
	offset := index * udpChunkSize
	chunk := min(udpChunkSize, size-offset)
	if len(frame) != udpFrameHeader+chunk {
		return nil, false
	}
	if count == 1 {
		return append([]byte{}, frame[udpFrameHeader:]...), true
	}
	p := d.pending[id]
	if p == nil {
		if d.pending == nil {
			d.pending = make(map[uint64]*udpAssembly)
		}
		if len(d.pending) >= udpMaxAssemblies {
			var oldest uint64
			var expires time.Time
			for k, a := range d.pending {
				if expires.IsZero() || a.expires.Before(expires) {
					oldest = k
					expires = a.expires
				}
			}
			delete(d.pending, oldest)
		}
		p = &udpAssembly{size: size, remaining: count, expires: now.Add(udpAssemblyLifetime)}
		d.pending[id] = p
	}
	if p.size != size {
		return nil, false
	}
	bit := uint64(1) << index
	if p.seen&bit != 0 {
		return nil, false
	}
	p.chunks[index] = append([]byte(nil), frame[udpFrameHeader:]...)
	p.seen |= bit
	p.remaining--
	if p.remaining != 0 {
		return nil, false
	}
	delete(d.pending, id)
	data := make([]byte, size)
	for i, chunk := range p.chunks {
		copy(data[min(i*udpChunkSize, size):], chunk)
	}
	return data, true
}

// FramedUDP preserves application datagrams over Tailcat's IPv6 MTU. It adds
// no retries, ordering or encryption; WireGuard provides encryption.
// Both ends of a published qcat UDP service must use this framing.
func FramedUDP(conn net.Conn) net.Conn {
	var seed [8]byte
	rand.Read(seed[:])
	return &framedUDP{Conn: conn, next: binary.BigEndian.Uint64(seed[:])}
}

type framedUDP struct {
	net.Conn
	readMu, writeMu sync.Mutex
	next            uint64
	decoder         udpDecoder
}

func (c *framedUDP) Write(packet []byte) (int, error) {
	if len(packet) > MaxUDPDatagram {
		return 0, errors.New("UDP datagram exceeds 65507 bytes")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.next++
	count := (len(packet) + udpChunkSize - 1) / udpChunkSize
	if count == 0 {
		count = 1
	}
	var frame [udpFrameLimit]byte
	copy(frame[:4], "QUD1")
	binary.BigEndian.PutUint64(frame[4:12], c.next)
	binary.BigEndian.PutUint16(frame[12:14], uint16(len(packet)))
	for index := 0; index < count; index++ {
		binary.BigEndian.PutUint16(frame[14:16], uint16(index))
		offset := index * udpChunkSize
		n := copy(frame[udpFrameHeader:], packet[offset:])
		size := udpFrameHeader + n
		written, err := c.Conn.Write(frame[:size])
		if err != nil {
			return 0, err
		}
		if written != size {
			return 0, io.ErrShortWrite
		}
	}
	return len(packet), nil
}
func (c *framedUDP) Read(dst []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var frame [udpFrameLimit + 1]byte
	for {
		n, err := c.Conn.Read(frame[:])
		if err != nil {
			clear(c.decoder.pending)
			return 0, err
		}
		packet, ok := c.decoder.accept(frame[:n], time.Now())
		if !ok {
			continue
		}
		if len(packet) > len(dst) {
			return 0, io.ErrShortBuffer
		}
		return copy(dst, packet), nil
	}
}

func proxyUDPDatagrams(a, b net.Conn) {
	done := make(chan struct{}, 2)
	pump := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buffer := make([]byte, MaxUDPDatagram+1)
		for {
			n, err := src.Read(buffer)
			if err != nil {
				return
			}
			if n > MaxUDPDatagram {
				continue
			}
			dst.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if written, err := dst.Write(buffer[:n]); err != nil || written != n {
				return
			}
		}
	}
	go pump(a, b)
	go pump(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}
