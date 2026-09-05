// Package server is the central runtime: the public mTLS ingest, the overlay-only
// console and status API, the state machine and the webhook worker.
package server

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

// ErrNotImplemented marks work packages that are scheduled but not built yet.
var ErrNotImplemented = errors.New("not implemented yet")

// Main dispatches the `excubra server` subcommands.
func Main(args []string) error {
	sub := "run"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "run":
		fs := flag.NewFlagSet("excubra server run", flag.ContinueOnError)
		envFile := fs.String("env-file", "", "KEY=value file with EXCUBRA_* settings (default /etc/excubra/server.env if present)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		_ = envFile
		return fmt.Errorf("server run: %w", ErrNotImplemented)
	case "user", "key", "backup", "prune":
		return fmt.Errorf("server %s: %w", sub, ErrNotImplemented)
	default:
		fmt.Fprintln(os.Stderr, "usage: excubra server [run|user|key|backup|prune] [flags]")
		return fmt.Errorf("server: unknown subcommand %q", sub)
	}
}
