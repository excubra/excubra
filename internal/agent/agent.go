// Package agent is the box-side runtime: enrollment, heartbeat loop, config pull,
// host checks, discovery and self-update. Phase 1 scope per salt "Konzept & Architektur".
package agent

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

// ErrNotImplemented marks work packages that are scheduled but not built yet.
var ErrNotImplemented = errors.New("not implemented yet")

// DefaultStateDir is where the agent keeps key, certificate, last config and buffer.
const DefaultStateDir = "/var/lib/excubra-agent"

// Main dispatches the `excubra agent` subcommands.
func Main(args []string) error {
	sub := "run"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "enroll":
		fs := flag.NewFlagSet("excubra agent enroll", flag.ContinueOnError)
		key := fs.String("key", "", "enrollment key (EX0:1:host:port:cafp:secret)")
		server := fs.String("server", "", "override the ingest host:port from the key")
		stateDir := fs.String("state-dir", DefaultStateDir, "state directory")
		if err := fs.Parse(args); err != nil {
			return err
		}
		_ = key
		_ = server
		_ = stateDir
		return fmt.Errorf("agent enroll: %w", ErrNotImplemented)
	case "run":
		fs := flag.NewFlagSet("excubra agent run", flag.ContinueOnError)
		stateDir := fs.String("state-dir", DefaultStateDir, "state directory")
		if err := fs.Parse(args); err != nil {
			return err
		}
		_ = stateDir
		return fmt.Errorf("agent run: %w", ErrNotImplemented)
	case "selftest":
		return fmt.Errorf("agent selftest: %w", ErrNotImplemented)
	default:
		fmt.Fprintln(os.Stderr, "usage: excubra agent [enroll|run|selftest] [flags]")
		return fmt.Errorf("agent: unknown subcommand %q", sub)
	}
}
