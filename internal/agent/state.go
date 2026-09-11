package agent

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/seal"
	"github.com/excubra/excubra/internal/wire"
)

// File names inside the state directory (ADR-0009). There is no config file: the
// identity is key + certificate + this directory, everything else is pulled.
const (
	fileKey      = "box.key"
	fileCert     = "box.crt"
	fileCA       = "ca.crt"
	fileServer   = "server" // "host:port" of the ingest
	fileCAFP     = "ca.fp"  // pinned CA fingerprint from the enrollment key
	fileBoxID    = "box.id" // informational, the certificate is authoritative
	fileConfig   = "config.json"
	dirBuffer    = "buffer"
	dirUpdate    = "update"
	fileEnroll   = "enroll"              // key left by the image inside the state dir, deleted after use
	enrollKeyEtc = "/etc/excubra/enroll" // read-only alternative for hand-made installs
)

// ErrNotEnrolled means the state directory holds no identity yet.
var ErrNotEnrolled = errors.New("agent: not enrolled — run `excubra agent enroll --key <KEY>`")

// State is the agent's on-disk identity and last known configuration.
type State struct {
	Dir string

	BoxID         string
	Server        string // host:port
	CAFingerprint string

	cert *tls.Certificate
	key  *ecdsa.PrivateKey
}

// OpenState prepares the state directory (0700) and loads an identity if present.
func OpenState(dir string) (*State, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("agent: state dir: %w", err)
	}
	for _, sub := range []string{dirBuffer, dirUpdate} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("agent: state dir: %w", err)
		}
	}
	s := &State{Dir: dir}
	s.Server = strings.TrimSpace(s.readFile(fileServer))
	s.CAFingerprint = strings.TrimSpace(s.readFile(fileCAFP))
	s.BoxID = strings.TrimSpace(s.readFile(fileBoxID))
	if err := s.loadCert(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// Enrolled reports whether the agent has an identity it can use.
func (s *State) Enrolled() bool {
	return s.cert != nil && s.Server != "" && s.CAFingerprint != ""
}

// Certificate returns the client certificate, or nil before enrollment.
func (s *State) Certificate() *tls.Certificate { return s.cert }

// Key returns the private key, generating and persisting one if none exists. The
// key survives re-enrollment attempts, so a failed enrollment does not leave the
// box with a key the server has never seen.
func (s *State) Key() (*ecdsa.PrivateKey, error) {
	if s.key != nil {
		return s.key, nil
	}
	if pemBytes, err := os.ReadFile(s.path(fileKey)); err == nil {
		k, err := pki.ParseKeyPEM(pemBytes)
		if err != nil {
			return nil, err
		}
		s.key = k
		return k, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("agent: reading key: %w", err)
	}
	k, err := pki.GenerateKey()
	if err != nil {
		return nil, err
	}
	pemBytes, err := pki.KeyPEM(k)
	if err != nil {
		return nil, err
	}
	if err := s.writeFile(fileKey, pemBytes, 0o600); err != nil {
		return nil, err
	}
	s.key = k
	return k, nil
}

// SaveIdentity stores what enrollment returned and loads it for immediate use.
func (s *State) SaveIdentity(boxID, certPEM, caPEM, server, caFingerprint string) error {
	if err := s.writeFile(fileCert, []byte(certPEM), 0o644); err != nil {
		return err
	}
	if err := s.writeFile(fileCA, []byte(caPEM), 0o644); err != nil {
		return err
	}
	if err := s.writeFile(fileServer, []byte(server+"\n"), 0o644); err != nil {
		return err
	}
	if err := s.writeFile(fileCAFP, []byte(caFingerprint+"\n"), 0o644); err != nil {
		return err
	}
	if err := s.writeFile(fileBoxID, []byte(boxID+"\n"), 0o644); err != nil {
		return err
	}
	s.BoxID, s.Server, s.CAFingerprint = boxID, server, caFingerprint
	return s.loadCert()
}

// SaveCertificate replaces the client certificate after a renewal.
func (s *State) SaveCertificate(certPEM string) error {
	if err := s.writeFile(fileCert, []byte(certPEM), 0o644); err != nil {
		return err
	}
	return s.loadCert()
}

// CertNotAfter returns the expiry of the current certificate.
func (s *State) CertNotAfter() (time.Time, error) {
	if s.cert == nil || s.cert.Leaf == nil {
		return time.Time{}, ErrNotEnrolled
	}
	return s.cert.Leaf.NotAfter, nil
}

func (s *State) loadCert() error {
	certPEM, err := os.ReadFile(s.path(fileCert))
	if err != nil {
		return err
	}
	key, err := s.Key()
	if err != nil {
		return err
	}
	keyPEM, err := pki.KeyPEM(key)
	if err != nil {
		return err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("agent: certificate does not match the key (delete %s to re-enroll): %w", s.Dir, err)
	}
	leaf, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return err
	}
	c.Leaf = leaf
	s.cert = &c
	if id, err := pki.BoxIDFromCert(leaf); err == nil {
		s.BoxID = id
	}
	return nil
}

// LoadConfig returns the last pulled configuration, so a box without network still
// checks the hosts it knew about.
func (s *State) LoadConfig() (wire.Config, bool) {
	b, err := os.ReadFile(s.path(fileConfig))
	if err != nil {
		return wire.Config{}, false
	}
	var c wire.Config
	if err := json.Unmarshal(b, &c); err != nil {
		return wire.Config{}, false
	}
	return c, true
}

// SaveConfig persists the configuration that is now in effect.
func (s *State) SaveConfig(c wire.Config) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.writeFile(fileConfig, b, 0o600)
}

// sealFile holds the box's X25519 seal key (ADR-0015): credentials for device APIs
// are sealed to its public half in the browser; only this box can open them.
const sealFile = "seal.key"

// SealKey loads the seal key, creating it on first use.
func (s *State) SealKey() (*ecdh.PrivateKey, error) {
	if raw := strings.TrimSpace(s.readFile(sealFile)); raw != "" {
		if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
			if k, err := seal.ParsePrivate(b); err == nil {
				return k, nil
			}
		}
	}
	k, err := seal.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := s.writeFile(sealFile, []byte(base64.StdEncoding.EncodeToString(k.Bytes())), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// taskFile remembers which tasks ran (so a re-pulled config never repeats one) and
// which results still wait for a successful heartbeat (ADR-0014).
const taskFile = "tasks.json"

// taskMemory is the on-disk shape of taskFile.
type taskMemory struct {
	Done    []string          `json:"done"`
	Results []wire.TaskResult `json:"results,omitempty"`
}

// maxDoneTasks bounds the remembered ids; the server expires tasks after an hour,
// so a few hundred ids cover every realistic replay.
const maxDoneTasks = 200

// LoadTasks returns the remembered task ids and the results not yet delivered.
func (s *State) LoadTasks() ([]string, []wire.TaskResult) {
	b, err := os.ReadFile(s.path(taskFile))
	if err != nil {
		return nil, nil
	}
	var m taskMemory
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, nil
	}
	return m.Done, m.Results
}

// SaveTasks persists the remembered ids (newest last, trimmed) and pending results.
func (s *State) SaveTasks(done []string, results []wire.TaskResult) error {
	if len(done) > maxDoneTasks {
		done = done[len(done)-maxDoneTasks:]
	}
	b, err := json.Marshal(taskMemory{Done: done, Results: results})
	if err != nil {
		return err
	}
	return s.writeFile(taskFile, b, 0o600)
}

// EnrollKeyPaths lists where a key file may lie: the explicit path, else the state
// directory, else /etc/excubra/enroll.
func EnrollKeyPaths(stateDir, explicit string) []string {
	if explicit != "" {
		return []string{explicit}
	}
	return []string{filepath.Join(stateDir, fileEnroll), enrollKeyEtc}
}

// ReadEnrollmentKey returns the first key found in the given paths, trimmed, and
// where it came from. Empty means there is none.
func ReadEnrollmentKey(paths ...string) (string, string) {
	for _, p := range paths {
		b, err := os.ReadFile(p) //nolint:gosec // operator-provided or well-known paths
		if err != nil {
			continue
		}
		if k := strings.TrimSpace(string(b)); k != "" {
			return k, p
		}
	}
	return "", ""
}

// DeleteEnrollmentKeyFile removes a used key file; a key is single-use, so leaving
// it on disk only invites confusion. /etc may be read-only for the service; then
// the file stays and the key is burned server-side anyway.
func DeleteEnrollmentKeyFile(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

func (s *State) path(name string) string { return filepath.Join(s.Dir, name) }

// writeFile writes atomically: a crash mid-write must never leave half a key.
func (s *State) writeFile(name string, data []byte, mode os.FileMode) error {
	full := s.path(name)
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("agent: writing %s: %w", name, err)
	}
	if err := os.Rename(tmp, full); err != nil {
		return fmt.Errorf("agent: writing %s: %w", name, err)
	}
	return nil
}

func (s *State) readFile(name string) string {
	b, err := os.ReadFile(s.path(name))
	if err != nil {
		return ""
	}
	return string(b)
}

// BufferDir and UpdateDir are where unsent heartbeats and downloaded binaries live.
func (s *State) BufferDir() string { return s.path(dirBuffer) }
func (s *State) UpdateDir() string { return s.path(dirUpdate) }
