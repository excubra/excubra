// Command sigcheck verifies a release signature the way a box does: with the public
// key compiled into this binary (internal/sig). The release workflow runs it so a
// mismatch between the signing key and the committed public key fails the release,
// not the first box that tries to update.
//
//	go run ./tools/sigcheck dist/excubra_linux_amd64 dist/excubra_linux_amd64.sig
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/excubra/excubra/internal/sig"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: sigcheck <file> <file.sig>")
		os.Exit(2)
	}
	blob, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "sigcheck:", err)
		os.Exit(1)
	}
	s, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "sigcheck:", err)
		os.Exit(1)
	}
	if err := sig.Verify(blob, strings.TrimSpace(string(s))); err != nil {
		fmt.Fprintln(os.Stderr, "sigcheck: FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("sigcheck: ok —", os.Args[1], "verifies against the embedded release key")
}
