// Package server is the central runtime: the public mTLS ingest, the overlay-only
// console and status API, the state machine and the webhook worker.
package server

import (
	"flag"
	"fmt"
	"os"
)

const usage = `usage: excubra server <command> [flags]

  run                       start the server (default)
  user   add|passwd|disable|enable|list
  key    new [--count N] [--note text] [--expires-days D]
  token  new --name X [--tenants a,b] | list | revoke <id>
  tenant add <slug> <name> | list
  site   add <tenant_id> <slug> <name> | list
  box    list | assign <box_id> <site_id> | unassign <box_id>
  backup <dir>
  prune  --keep <days>

Every command reads /etc/excubra/server.env or --env-file.
`

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
		return run(*envFile)
	case "user":
		return userCmd(args)
	case "key":
		return keyCmd(args)
	case "token":
		return tokenCmd(args)
	case "tenant":
		return tenantCmd(args)
	case "site":
		return siteCmd(args)
	case "box":
		return boxCmd(args)
	case "release":
		return releaseCmd(args)
	case "backup":
		return backupCmd(args)
	case "prune":
		return pruneCmd(args)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("server: unknown subcommand %q", sub)
	}
}
