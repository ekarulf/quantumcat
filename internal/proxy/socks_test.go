package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKSAllowAndDeny(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	for _, allow := range []bool{false, true} {
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			Serve(b, func(target string) bool { return allow && target == echo.Addr().String() })
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := Dial(ctx, a, echo.Addr().String())
		cancel()
		if !allow {
			if err == nil {
				t.Fatal("denied target opened")
			}
			<-done
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err = c.Write([]byte("qcat")); err != nil {
			t.Fatal(err)
		}
		p := make([]byte, 4)
		if _, err = io.ReadFull(c, p); err != nil || string(p) != "qcat" {
			t.Fatalf("echo: %q %v", p, err)
		}
		c.Close()
		<-done
	}
}
