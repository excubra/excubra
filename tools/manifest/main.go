// Command manifest writes the release manifest the server catalog reads (ADR-0006):
// version, minimum agent version, and for every built binary its download URL,
// SHA-256 and signature. Run by the release workflow after signing:
//
//	go run ./tools/manifest -dir dist -version 0.2.0 -base-url https://github.com/excubra/excubra/releases/download/v0.2.0 > dist/manifest.json
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type file struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

type manifest struct {
	Version         string `json:"version"`
	MinAgentVersion string `json:"min_agent_version,omitempty"`
	Files           []file `json:"files"`
}

func main() {
	dir := flag.String("dir", "dist", "directory with SHA256SUMS and .sig files")
	version := flag.String("version", "", "release version without the v")
	base := flag.String("base-url", "", "URL prefix the files are published under")
	minAgent := flag.String("min-agent", "", "oldest agent allowed to install this release")
	flag.Parse()
	if *version == "" || *base == "" {
		fmt.Fprintln(os.Stderr, "manifest: -version and -base-url are required")
		os.Exit(2)
	}
	sums, err := os.Open(filepath.Join(*dir, "SHA256SUMS"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest:", err)
		os.Exit(1)
	}
	defer sums.Close()
	m := manifest{Version: strings.TrimPrefix(*version, "v"), MinAgentVersion: *minAgent}
	sc := bufio.NewScanner(sums)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		rest, ok := strings.CutPrefix(name, "excubra_linux_")
		if !ok || (rest != "amd64" && rest != "arm64") {
			continue
		}
		sig, err := os.ReadFile(filepath.Join(*dir, name+".sig"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "manifest:", err)
			os.Exit(1)
		}
		m.Files = append(m.Files, file{OS: "linux", Arch: rest, Name: name, URL: strings.TrimSuffix(*base, "/") + "/" + name, SHA256: strings.ToLower(fields[0]), Signature: strings.TrimSpace(string(sig))})
	}
	if len(m.Files) == 0 {
		fmt.Fprintln(os.Stderr, "manifest: no excubra_linux_* entries in SHA256SUMS")
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		fmt.Fprintln(os.Stderr, "manifest:", err)
		os.Exit(1)
	}
}
