// Package control provides same-user local status and shutdown over a protected
// Unix socket. It has no network listener and never returns key material.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func Start(ctx context.Context, dir, name string, status func() any, stop func()) (func(), error) {
	return StartPeer(ctx, dir, name, "", status, stop)
}

// StartPeer records peer identity explicitly, independent of runtime names.
func StartPeer(ctx context.Context, dir, name, peer string, status func() any, stop func()) (func(), error) {
	dir = filepath.Join(dir, "run")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("runtime directory must have mode 0700")
	}
	path := filepath.Join(dir, name+".sock")
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("runtime path is not a socket")
		}
		c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil, errors.New("this Quantumcat command is already running")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		ln.Close()
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.SetDeadline(time.Now().Add(time.Second))
			var req struct{ Command string }
			d := json.NewDecoder(io.LimitReader(c, 128))
			err = d.Decode(&req)
			if err == nil {
				switch req.Command {
				case "info":
					json.NewEncoder(c).Encode(struct{ Peer string }{peer})
				case "status":
					json.NewEncoder(c).Encode(status())
				case "stop":
					json.NewEncoder(c).Encode(map[string]string{"stopping": name})
					stop()
				default:
					json.NewEncoder(c).Encode(map[string]string{"error": "unknown command"})
				}
			}
			c.Close()
		}
	}()
	unhook := context.AfterFunc(ctx, func() { ln.Close() })
	return func() { unhook(); ln.Close(); <-done }, nil
}

func Query(dir, name, command string) (map[string]json.RawMessage, error) {
	if name != "" && (strings.ContainsAny(name, "/\\") || name == "." || name == "..") {
		return nil, errors.New("invalid runtime name")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "run"))
	if os.IsNotExist(err) {
		return map[string]json.RawMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]json.RawMessage{}
	// An exact runtime name takes precedence over any peer with the same name.
	runtimeTarget := false
	for _, e := range entries {
		if name != "" && e.Name() == name+".sock" && e.Type()&os.ModeSocket != 0 {
			runtimeTarget = true
		}
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sock") || e.Type()&os.ModeSocket == 0 {
			continue
		}
		n := strings.TrimSuffix(e.Name(), ".sock")
		path := filepath.Join(dir, "run", e.Name())
		if name != "" && n != name {
			if runtimeTarget {
				continue
			}
			b, err := request(path, "info")
			var info struct{ Peer string }
			if err != nil || json.Unmarshal(b, &info) != nil || info.Peer != name {
				continue
			}
		}
		b, err := request(path, command)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
				continue
			}
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		if !json.Valid(b) {
			return nil, fmt.Errorf("%s: invalid runtime response", n)
		}
		out[n] = json.RawMessage(b)
	}
	return out, nil
}

func request(path, command string) ([]byte, error) {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := json.NewEncoder(c).Encode(map[string]string{"Command": command}); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(c, 1<<20))
}
