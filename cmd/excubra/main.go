// Command excubra is the single binary of EX0: `excubra agent` runs on the box,
// `excubra server` in the centre. Subcommand dispatch only — no logic lives here.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/excubra/excubra/internal/agent"
	"github.com/excubra/excubra/internal/server"
	"github.com/excubra/excubra/internal/version"
)

const usage = `excubra — EX0 (Excubra Zero)

usage:
  excubra agent  [enroll|run|selftest] [flags]   the box-side agent
  excubra server [run|user|key|backup|prune]     the central server
  excubra version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "agent":
		err = agent.Main(os.Args[2:])
	case "server":
		err = server.Main(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println(version.String())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "excubra: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if errors.Is(err, agent.ErrRestart) {
		// a self-update replaced the binary; 75 tells systemd (SuccessExitStatus=75) to start the new one
		os.Exit(75)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "excubra:", err)
		os.Exit(1)
	}
}
