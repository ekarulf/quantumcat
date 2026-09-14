package se

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestReloadHelperChild(t *testing.T) {
	mode := os.Getenv("QCAT_TEST_RELOAD_HELPER")
	if mode == "" {
		return
	}
	for {
		var header [4]byte
		if _, err := io.ReadFull(os.Stdin, header[:]); err != nil {
			os.Exit(0)
		}
		b := make([]byte, binary.BigEndian.Uint32(header[:]))
		if _, err := io.ReadFull(os.Stdin, b); err != nil {
			os.Exit(1)
		}
		reply := []byte{0}
		switch b[0] {
		case 2:
			if !bytes.Equal(b[1:], []byte("opaque-reference")) {
				os.Exit(2)
			}
		case 3:
			reply = append(reply, []byte("pinned-public")...)
			if mode == "wrong-key" {
				reply = append(reply, '!')
			}
		case 4:
			if mode == "stall" {
				time.Sleep(time.Minute)
			}
			reply = append(reply, []byte("signature")...)
		default:
			os.Exit(3)
		}
		binary.BigEndian.PutUint32(header[:], uint32(len(reply)))
		os.Stdout.Write(header[:])
		os.Stdout.Write(reply)
	}
}

func TestIdentityReloadsAfterTimeout(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-key", true: "changed-key"}[wrong], func(t *testing.T) {
			opens := 0
			open := func() (*Helper, error) {
				mode := "ok"
				if opens == 0 {
					mode = "stall"
				} else if wrong {
					mode = "wrong-key"
				}
				opens++
				cmd := exec.Command(os.Args[0], "-test.run=^TestReloadHelperChild$")
				cmd.Env = append(os.Environ(), "QCAT_TEST_RELOAD_HELPER="+mode)
				return start(cmd)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			i, err := openIdentity(ctx, []byte("opaque-reference"), open)
			if err != nil {
				t.Fatal(err)
			}
			defer i.Close()
			expired, stop := context.WithCancel(ctx)
			stop()
			if _, err = i.Sign(expired, "label", nil); err == nil {
				t.Fatal("cancelled sign succeeded")
			}
			if opens != 1 {
				t.Fatal("pre-cancelled operation restarted helper")
			}
			short, stop := context.WithTimeout(ctx, 50*time.Millisecond)
			if _, err = i.Sign(short, "label", nil); err == nil {
				t.Fatal("stalled sign succeeded")
			}
			stop()
			got, err := i.Sign(ctx, "label", nil)
			if wrong {
				if err == nil {
					t.Fatal("changed identity accepted")
				}
			} else if err != nil || string(got) != "signature" {
				t.Fatalf("reload: %q %v", got, err)
			}
			if opens != 2 {
				t.Fatalf("opens=%d", opens)
			}
			i.Close()
			if _, err = i.Sign(ctx, "label", nil); err == nil {
				t.Fatal("closed identity reopened")
			}
		})
	}
}
