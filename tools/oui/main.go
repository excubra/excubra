// Command oui downloads the IEEE OUI registry and writes the compact vendor table
// the agent embeds (internal/agent/discovery/oui.tsv.gz): one line per 24-bit
// prefix, "AABBCC<TAB>Vendor", sorted, gzip-compressed. Run with `make oui`.
package main

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const source = "https://standards-oui.ieee.org/oui/oui.csv"

func main() {
	out := "internal/agent/discovery/oui.tsv.gz"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		fail(err)
	}
	// the IEEE site answers Go's default user agent with 418
	req.Header.Set("User-Agent", "curl/8.0 (excubra oui table generator)")
	resp, err := client.Do(req)
	if err != nil {
		fail(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		fail(fmt.Errorf("%s: HTTP %d", source, resp.StatusCode))
	}
	r := csv.NewReader(resp.Body)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	vendors := map[string]string{}
	header := true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(err)
		}
		if header {
			header = false
			continue
		}
		if len(rec) < 3 || rec[0] != "MA-L" {
			continue
		}
		prefix := strings.ToUpper(strings.TrimSpace(rec[1]))
		name := strings.Join(strings.Fields(rec[2]), " ")
		if len(prefix) != 6 || name == "" {
			continue
		}
		vendors[prefix] = name
	}
	keys := make([]string, 0, len(vendors))
	for k := range vendors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	f, err := os.Create(out) //nolint:gosec // output path from the operator's command line
	if err != nil {
		fail(err)
	}
	gz, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	for _, k := range keys {
		_, _ = fmt.Fprintf(gz, "%s\t%s\n", k, vendors[k])
	}
	if err := gz.Close(); err != nil {
		fail(err)
	}
	if err := f.Close(); err != nil {
		fail(err)
	}
	st, _ := os.Stat(out) //nolint:gosec // same operator path
	fmt.Printf("%d vendors → %s (%d bytes)\n", len(keys), out, st.Size())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "oui:", err)
	os.Exit(1)
}
