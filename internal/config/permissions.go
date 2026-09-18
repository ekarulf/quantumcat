package config

import (
	"os"
	"path/filepath"

	"github.com/ekarulf/quantumcat/internal/trust"
)

// Public peer keys are not confidential, but their integrity is authorization.
// Root-owned 0750 directories and 0640 files support a root-managed service.
func trustedPath(path string, directory bool) error {
	return trust.Path(path, directory)
}

func trustedOwner(info os.FileInfo) error {
	return trust.Owner(info)
}

func (s Store) checkStore() error {
	path, err := filepath.Abs(s.Dir)
	if err != nil {
		return err
	}
	if err := trustedPath(path, true); err != nil {
		return err
	}
	return trust.Ancestors(path)
}

func (s Store) checkPeers() error {
	if err := s.checkStore(); err != nil {
		return err
	}
	return trustedPath(filepath.Join(s.Dir, "peers"), true)
}
