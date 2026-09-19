package config

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/ekarulf/quantumcat/internal/crypto/provider"
	"github.com/ekarulf/quantumcat/internal/crypto/provider/se"
	"github.com/ekarulf/quantumcat/internal/crypto/provider/software"
	"github.com/ekarulf/quantumcat/internal/protocol"
	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
)

const (
	MaxFile         = 128 * 1024
	IdentityVersion = 3
	PeerVersion     = 1
)

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func CheckName(name string) error {
	if !nameRE.MatchString(name) {
		return errors.New("name must be 1–64 letters, digits, hyphens or underscores")
	}
	return nil
}

type IdentityFile struct {
	Version        int
	Name, Provider string
	Private        []byte
	Node           key.NodePrivate
}
type Peer struct {
	Version   int
	Name      string
	PeerID    string
	PublicKey []byte
	Endpoint  tailcat.Addr `json:",omitempty"`
}

func (p Peer) Validate() error {
	if p.Version != PeerVersion {
		return errors.New("unsupported peer version")
	}
	if err := CheckName(p.Name); err != nil {
		return err
	}
	if len(p.PublicKey) != mldsa.MLDSA87PublicKeySize || p.PeerID != protocol.ID(p.PublicKey).String() {
		return errors.New("peer identity key/PeerID mismatch")
	}
	if p.Endpoint != "" {
		ci, err := tailcat.ParseAddr(p.Endpoint)
		if err != nil {
			return err
		}
		if !ci.PresharedKey.IsZero() {
			return errors.New("public endpoint must not contain a PSK")
		}
		if ci.ServerPublic.IsZero() || ci.ServerDiscoPublic.IsZero() {
			return errors.New("endpoint missing public transport keys")
		}
	}
	return nil
}

type Store struct{ Dir string }

func DefaultDir() string {
	if s := os.Getenv("QCAT_CONFIG_DIR"); s != "" {
		return s
	}
	if s := os.Getenv("XDG_CONFIG_HOME"); s != "" {
		return filepath.Join(s, "qcat")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "qcat")
}
func Read(path string, out any, secret bool) error {
	return read(path, out, secret, false)
}
func read(path string, out any, secret, authorization bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxFile {
		return errors.New("invalid config file")
	}
	if secret && st.Mode().Perm()&0077 != 0 {
		return errors.New("identity file must have mode 0600")
	}
	if secret || authorization {
		if err := trustedOwner(st); err != nil {
			return err
		}
		if st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("%s: authorization file is group/other writable", path)
		}
		if err := trustedPath(path, false); err != nil {
			return err
		}
		current, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !os.SameFile(st, current) {
			return fmt.Errorf("%s: file changed while opening", path)
		}
	}
	d := json.NewDecoder(io.LimitReader(f, MaxFile+1))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing config data")
	}
	return nil
}
func WriteNew(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	defer clear(b)
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		os.Remove(path)
		return err
	}
	return closeErr
}
func (s Store) Init(ctx context.Context, name, kind string) error {
	if err := CheckName(name); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	if err := s.checkStore(); err != nil {
		return err
	}
	if kind == "" {
		kind = "software"
		if runtime.GOOS == "darwin" {
			kind = "secure-enclave"
		}
	}
	f := IdentityFile{Version: IdentityVersion, Name: name, Provider: kind, Node: key.NewNode()}
	switch kind {
	case "software":
		i, err := software.Generate()
		if err != nil {
			return err
		}
		f.Private = i.Bytes()
	case "secure-enclave":
		h, err := se.Open()
		if err != nil {
			return err
		}
		defer h.Close()
		f.Private, err = h.GenerateIdentity(ctx)
		if err != nil {
			return err
		}
	default:
		return errors.New("provider must be software or secure-enclave")
	}
	defer clear(f.Private)
	return WriteNew(filepath.Join(s.Dir, "identity.json"), f)
}
func (s Store) Identity(ctx context.Context) (provider.Identity, provider.NewKEM, IdentityFile, func(), error) {
	var f IdentityFile
	if err := s.checkStore(); err != nil {
		return nil, nil, f, func() {}, err
	}
	if err := Read(filepath.Join(s.Dir, "identity.json"), &f, true); err != nil {
		return nil, nil, f, func() {}, err
	}
	defer clear(f.Private)
	if f.Version != IdentityVersion {
		return nil, nil, f, func() {}, errors.New("unsupported identity file version; reinitialize and re-pair for the SHA-512/256 PeerID migration")
	}
	if f.Node.IsZero() {
		return nil, nil, f, func() {}, errors.New("invalid identity file")
	}
	switch f.Provider {
	case "software":
		i, err := software.Load(f.Private)
		if err != nil {
			return nil, nil, f, func() {}, err
		}
		return i, software.NewKEM, f, i.Destroy, nil
	case "secure-enclave":
		h, err := se.OpenIdentity(ctx, f.Private)
		if err != nil {
			return nil, nil, f, func() {}, err
		}
		return h, se.NewKEM, f, h.Close, nil
	default:
		return nil, nil, f, func() {}, errors.New("unknown identity provider")
	}
}
func (s Store) Peer(name string) (Peer, error) {
	var p Peer
	if err := CheckName(name); err != nil {
		return p, err
	}
	if err := s.checkPeers(); err != nil {
		return p, err
	}
	if err := trustedPath(filepath.Join(s.Dir, "peers", name+".qpeer"), false); err != nil {
		return p, err
	}
	err := read(filepath.Join(s.Dir, "peers", name+".qpeer"), &p, false, true)
	if err != nil {
		return p, err
	}
	return p, p.Validate()
}
func (s Store) Peers() ([]Peer, error) {
	if err := s.checkPeers(); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(s.Dir, "peers"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var peers []Peer
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".qpeer" {
			continue
		}
		var p Peer
		if err = trustedPath(filepath.Join(s.Dir, "peers", e.Name()), false); err != nil {
			return nil, err
		}
		if err = read(filepath.Join(s.Dir, "peers", e.Name()), &p, false, true); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if err = p.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		peers = append(peers, p)
	}
	return peers, nil
}
func (s Store) Add(name, path string) error {
	if err := CheckName(name); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	if err := s.checkStore(); err != nil {
		return err
	}
	var p Peer
	if err := Read(path, &p, false); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	peers, err := s.Peers()
	if err != nil {
		return err
	}
	for _, existing := range peers {
		if bytes.Equal(existing.PublicKey, p.PublicKey) {
			return errors.New("identity already paired")
		}
	}
	p.Name = name
	return WriteNew(filepath.Join(s.Dir, "peers", name+".qpeer"), p)
}

// Remove moves the descriptor aside, allowing recovery and preserving an audit artifact.
func (s Store) Remove(name string) error {
	if _, err := s.Peer(name); err != nil {
		return err
	}
	src := filepath.Join(s.Dir, "peers", name+".qpeer")
	dst := src + ".revoked"
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		return errors.New("existing revoked backup; move it before removing again")
	}
	return os.Rename(src, dst)
}
