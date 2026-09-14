// Package proxy implements bounded SOCKS5 CONNECT negotiation.
package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/tailscale/tailcat"
)

func Dial(ctx context.Context, c net.Conn, target string) (net.Conn, error) {
	fail := func(err error) (net.Conn, error) { c.Close(); return nil, err }
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 || len(host) == 0 || len(host) > 255 {
		return fail(errors.New("invalid proxy target"))
	}
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	var reply [2]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		return fail(err)
	}
	if reply != [2]byte{5, 0} {
		return fail(errors.New("proxy authentication rejected"))
	}
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	request = binary.BigEndian.AppendUint16(request, uint16(n))
	if _, err = c.Write(request); err != nil {
		return fail(err)
	}
	var header [4]byte
	if _, err = io.ReadFull(c, header[:]); err != nil {
		return fail(err)
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return fail(errors.New("remote target denied or unavailable"))
	}
	if _, err = readAddress(c, header[3]); err != nil {
		return fail(err)
	}
	c.SetDeadline(time.Time{})
	return c, nil
}
func readAddress(r io.Reader, kind byte) (string, error) {
	var host string
	switch kind {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		if n[0] == 0 {
			return "", errors.New("empty host")
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("unsupported address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}
func Serve(c net.Conn, allowed func(string) bool) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	found := false
	for _, m := range methods {
		found = found || m == 0
	}
	if !found {
		c.Write([]byte{5, 255})
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(c, request[:]); err != nil {
		return
	}
	reply := func(code byte) { c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if request[0] != 5 || request[1] != 1 || request[2] != 0 {
		reply(7)
		return
	}
	target, err := readAddress(c, request[3])
	if err != nil {
		reply(8)
		return
	}
	if !allowed(target) {
		reply(2)
		return
	}
	out, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		reply(5)
		return
	}
	defer out.Close()
	reply(0)
	c.SetDeadline(time.Time{})
	tailcat.ProxyConns(c, out)
}
func ValidateTarget(target string) error {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 || h == "" {
		return fmt.Errorf("invalid target %q", target)
	}
	return nil
}
