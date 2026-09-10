// Package agent is the box-side runtime: enrollment, heartbeat loop, config pull,
// host checks, discovery, NetBird hand-over and self-update. Phase 1 scope per
// salt "Konzept & Architektur — Box und Phase 1".
package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/excubra/excubra/internal/agent/update"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

// DefaultStateDir is where the agent keeps key, certificate, last config and buffer.
const DefaultStateDir = "/var/lib/excubra-agent"

// ErrRestart is returned by Run after a self-update; main exits 75 on it.
var ErrRestart = update.ErrRestart

// Main dispatches the `excubra agent` subcommands.
func Main(args []string) error {
	sub := "run"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		sub, args = args[0], args[1:]
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	switch sub {
	case "enroll":
		fs := flag.NewFlagSet("excubra agent enroll", flag.ContinueOnError)
		key := fs.String("key", "", "enrollment key (EX0:1:host:port:cafp:secret)")
		keyFile := fs.String("key-file", "", "read the key from this file instead (default /etc/excubra/enroll)")
		server := fs.String("server", "", "override the ingest host:port from the key")
		stateDir := fs.String("state-dir", DefaultStateDir, "state directory")
		if err := fs.Parse(args); err != nil {
			return err
		}
		k := strings.TrimSpace(*key)
		if k == "" {
			k = ReadEnrollmentKey(*keyFile)
		}
		if k == "" {
			return errors.New("agent enroll: no key given (--key) and no key file found")
		}
		st, err := OpenState(*stateDir)
		if err != nil {
			return err
		}
		if st.Enrolled() {
			return fmt.Errorf("agent enroll: already enrolled as %s (delete %s to start over)", st.BoxID, st.Dir)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := Enroll(ctx, st, k, *server, log); err != nil {
			return err
		}
		if *key == "" {
			DeleteEnrollmentKeyFile(*keyFile)
		}
		fmt.Printf("enrolled as %s at %s\n", st.BoxID, st.Server)
		return nil

	case "run":
		fs := flag.NewFlagSet("excubra agent run", flag.ContinueOnError)
		stateDir := fs.String("state-dir", DefaultStateDir, "state directory")
		enrollFile := fs.String("enroll-file", "", "enrollment key file the image left behind (default /etc/excubra/enroll)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return Run(ctx, *stateDir, *enrollFile, log)

	case "selftest":
		fs := flag.NewFlagSet("excubra agent selftest", flag.ContinueOnError)
		stateDir := fs.String("state-dir", DefaultStateDir, "state directory")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return Selftest(*stateDir)

	default:
		fmt.Fprintln(os.Stderr, "usage: excubra agent [enroll|run|selftest] [flags]")
		return fmt.Errorf("agent: unknown subcommand %q", sub)
	}
}

// Enroll turns a one-time key into a box identity (ADR-0010).
func Enroll(ctx context.Context, st *State, keyStr, serverOverride string, log *slog.Logger) error {
	key, err := pki.ParseEnrollmentKey(keyStr)
	if err != nil {
		return err
	}
	server := key.Address()
	if serverOverride != "" {
		server = serverOverride
	}
	client, err := NewClient(server, key.CAFingerprint, nil)
	if err != nil {
		return err
	}
	priv, err := st.Key()
	if err != nil {
		return err
	}
	hw := hardwareID()
	csr, err := pki.CSRPEM(priv, hw)
	if err != nil {
		return err
	}
	resp, err := client.Enroll(ctx, wire.EnrollRequest{Key: keyStr, HWID: hw, CSR: string(csr), AgentVersion: version.Version, OS: runtime.GOOS, Arch: runtime.GOARCH})
	if err != nil {
		return fmt.Errorf("enrollment refused: %w", err)
	}
	ca, err := pki.ParseCertPEM([]byte(resp.CA))
	if err != nil {
		return fmt.Errorf("enrollment: server sent an unreadable CA: %w", err)
	}
	if pki.FingerprintOf(ca) != key.CAFingerprint {
		return errors.New("enrollment: the CA the server sent does not match the pinned fingerprint")
	}
	if err := st.SaveIdentity(resp.BoxID, resp.Certificate, resp.CA, server, key.CAFingerprint); err != nil {
		return err
	}
	log.Info("enrolled", "box", resp.BoxID, "server", server, "cert_not_after", resp.NotAfter)
	return nil
}

// Selftest is what a freshly downloaded binary runs before it is installed
// (ADR-0006): load the identity and pull the config once.
func Selftest(stateDir string) error {
	st, err := OpenState(stateDir)
	if err != nil {
		return err
	}
	if !st.Enrolled() {
		return ErrNotEnrolled
	}
	client, err := NewClient(st.Server, st.CAFingerprint, st)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, _, err := client.Config(ctx, ""); err != nil {
		return fmt.Errorf("selftest: %w", err)
	}
	fmt.Println("selftest ok:", version.String())
	return nil
}
