// Package se talks to the Swift helper exclusively over inherited pipes.
package se

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/ekarulf/quantumcat/internal/crypto/provider"
)

type Helper struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    io.ReadCloser
	closed bool
	done   chan struct{}
}

func Open() (*Helper, error) {
	path, err := helperPath()
	if err != nil {
		return nil, err
	}
	return start(exec.Command(path))
}

func helperPath() (string, error) {
	path := os.Getenv("QCAT_ENCLAVE_HELPER")
	if path == "" {
		path = os.Getenv("QCAT_SE_HELPER") // Compatibility with existing LaunchAgents.
	}
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		path = filepath.Join(filepath.Dir(exe), "qcat-se")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("QCAT_ENCLAVE_HELPER must be an absolute path")
	}
	return path, nil
}

func start(cmd *exec.Cmd) (*Helper, error) {
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		in.Close()
		out.Close()
		return nil, fmt.Errorf("start Secure Enclave helper (run make helper): %w", err)
	}
	h := &Helper{cmd: cmd, in: in, out: out, done: make(chan struct{})}
	go func() {
		cmd.Wait()
		close(h.done)
	}()
	return h, nil
}

// Done closes when the helper exits, including cancellation or unexpected death.
// A daemon must not continue accepting work with this dead identity provider.
func (h *Helper) Done() <-chan struct{} { return h.done }
func (h *Helper) call(ctx context.Context, op byte, payload []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, errors.New("Secure Enclave helper closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	killed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { h.cmd.Process.Kill(); close(killed) })
	defer func() {
		if !stop() {
			<-killed
		}
	}()
	if len(payload) > 32767 {
		return nil, errors.New("helper request too large")
	}
	b := make([]byte, 5, len(payload)+5)
	binary.BigEndian.PutUint32(b, uint32(len(payload)+1))
	b[4] = op
	b = append(b, payload...)
	if _, err := h.in.Write(b); err != nil {
		return nil, err
	}
	var size [4]byte
	if _, err := io.ReadFull(h.out, size[:]); err != nil {
		return nil, fmt.Errorf("Secure Enclave helper unavailable: %w", err)
	}
	n := binary.BigEndian.Uint32(size[:])
	if n < 1 || n > 32768 {
		return nil, errors.New("invalid helper response size")
	}
	reply := make([]byte, n)
	if _, err := io.ReadFull(h.out, reply); err != nil {
		return nil, err
	}
	if reply[0] != 0 {
		return nil, fmt.Errorf("Secure Enclave: %s", reply[1:])
	}
	return reply[1:], nil
}
func (h *Helper) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed {
		h.closed = true
		h.in.Close()
		h.cmd.Process.Kill()
		h.out.Close()
		<-h.done
	}
}
func (h *Helper) GenerateIdentity(ctx context.Context) ([]byte, error) { return h.call(ctx, 1, nil) }
func (h *Helper) LoadIdentity(ctx context.Context, ref []byte) error {
	_, err := h.call(ctx, 2, ref)
	return err
}
func (h *Helper) PublicKey(ctx context.Context) ([]byte, error) { return h.call(ctx, 3, nil) }
func (h *Helper) Sign(ctx context.Context, label string, msg []byte) ([]byte, error) {
	if len(label) > 255 {
		return nil, errors.New("signature context too long")
	}
	return h.call(ctx, 4, append(append([]byte{byte(len(label))}, []byte(label)...), msg...))
}
func (h *Helper) Capabilities(ctx context.Context) ([]byte, error) { return h.call(ctx, 9, nil) }

type ephemeral struct{ *Helper }

func NewKEM(ctx context.Context) (provider.KEM, error) {
	h, err := Open()
	if err != nil {
		return nil, err
	}
	if _, err = h.call(ctx, 5, nil); err != nil {
		h.Close()
		return nil, err
	}
	return &ephemeral{h}, nil
}
func (k *ephemeral) PublicKey(ctx context.Context) ([]byte, error) { return k.call(ctx, 6, nil) }
func (k *ephemeral) Decapsulate(ctx context.Context, ct []byte) ([]byte, error) {
	return k.call(ctx, 7, ct)
}
func (k *ephemeral) Destroy() { k.Close() }
