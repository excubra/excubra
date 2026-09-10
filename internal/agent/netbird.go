package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// Netbird drives the NetBird client on the box through its CLI. The client is a
// separate, version-pinned service on the image; the agent only reports its state
// and hands it the setup key once (ADR-0010).
type Netbird struct {
	Binary   string // "netbird" on PATH by default
	StateDir string
	Exec     func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// NewNetbird returns the production controller.
func NewNetbird(stateDir string) *Netbird {
	return &Netbird{Binary: "netbird", StateDir: stateDir, Exec: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}}
}

// Status reports the client's state for the heartbeat. A box without the client
// reports not_configured; the server treats that as "no overlay", not as an error.
func (n *Netbird) Status(ctx context.Context) wire.NetbirdInfo {
	if _, err := exec.LookPath(n.Binary); err != nil {
		return wire.NetbirdInfo{Status: wire.NetbirdNotConfigured}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := n.Exec(ctx, n.Binary, "status", "--json")
	if err != nil {
		msg := strings.ToLower(string(out))
		if strings.Contains(msg, "not logged in") || strings.Contains(msg, "needslogin") || strings.Contains(msg, "login") {
			return wire.NetbirdInfo{Status: wire.NetbirdNotConfigured}
		}
		return wire.NetbirdInfo{Status: wire.NetbirdError}
	}
	var st struct {
		Management struct {
			URL       string `json:"url"`
			Connected bool   `json:"connected"`
		} `json:"management"`
		NetbirdIP     string `json:"netbirdIp"`
		DaemonVersion string `json:"daemonVersion"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return wire.NetbirdInfo{Status: wire.NetbirdError}
	}
	info := wire.NetbirdInfo{Status: wire.NetbirdDisconnected, ManagementURL: st.Management.URL, Version: st.DaemonVersion}
	if ip, _, ok := strings.Cut(st.NetbirdIP, "/"); ok {
		info.IP = ip
	} else {
		info.IP = st.NetbirdIP
	}
	if st.Management.URL == "" {
		info.Status = wire.NetbirdNotConfigured
	} else if st.Management.Connected {
		info.Status = wire.NetbirdConnected
	}
	return info
}

// Up connects the client to a management server with a setup key. The key goes
// through a 0600 file, never through the process list, and is deleted afterwards.
func (n *Netbird) Up(ctx context.Context, managementURL, setupKey string) error {
	if _, err := exec.LookPath(n.Binary); err != nil {
		return errors.New("netbird client is not installed on this box")
	}
	keyFile := filepath.Join(n.StateDir, "netbird-setup-key")
	if err := os.WriteFile(keyFile, []byte(setupKey), 0o600); err != nil {
		return fmt.Errorf("netbird: %w", err)
	}
	defer func() { _ = os.Remove(keyFile) }()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := n.Exec(ctx, n.Binary, "up", "--management-url", managementURL, "--setup-key-file", keyFile)
	if err != nil {
		return fmt.Errorf("netbird up: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
