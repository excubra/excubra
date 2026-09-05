package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEnvFile(t *testing.T) {
	in := `
# comment
EXCUBRA_DATA_DIR=/data
export EXCUBRA_INGEST_LISTEN=":8443"
EXCUBRA_OVERLAY_LISTEN='100.64.0.5:8080'
EMPTY=
`
	m, err := ParseEnvFile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if m["EXCUBRA_DATA_DIR"] != "/data" || m["EXCUBRA_INGEST_LISTEN"] != ":8443" || m["EXCUBRA_OVERLAY_LISTEN"] != "100.64.0.5:8080" || m["EMPTY"] != "" {
		t.Fatalf("parsed: %v", m)
	}
	if _, err := ParseEnvFile(strings.NewReader("NOEQUALS\n")); err == nil {
		t.Fatal("line without = accepted")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "server.env")
	if err := os.WriteFile(envFile, []byte("EXCUBRA_INGEST_PUBLIC_HOST=ingest.example.test\nEXCUBRA_OVERLAY_LISTEN=100.64.0.5:8080\nEXCUBRA_DATA_DIR=/from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"EXCUBRA_DATA_DIR": "/from-env"}
	c, err := LoadConfig(envFile, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/from-env" || c.IngestPublicHost != "ingest.example.test" || c.OverlayListen != "100.64.0.5:8080" {
		t.Fatalf("config: %+v", c)
	}
	h, p := c.IngestHostPort()
	if h != "ingest.example.test" || p != "443" {
		t.Fatalf("host/port: %s %s", h, p)
	}
	if c.ConsoleBaseURL() != "http://100.64.0.5:8080" {
		t.Fatalf("console url: %s", c.ConsoleBaseURL())
	}
	if _, err := LoadConfig(filepath.Join(dir, "missing.env"), func(string) string { return "" }); err == nil {
		t.Fatal("missing explicit env file accepted")
	}
}

func TestValidateRefusesWildcardOverlay(t *testing.T) {
	base := Config{DataDir: "/d", IngestListen: ":443", IngestPublicHost: "1.2.3.4", OverlayTLS: "off", LogLevel: "info", LogFormat: "text"}
	for _, bad := range []string{"", ":8080", "0.0.0.0:8080", "[::]:8080", "localhost:8080", "100.64.0.5"} {
		c := base
		c.OverlayListen = bad
		if err := c.Validate(); err == nil {
			t.Errorf("overlay %q accepted", bad)
		}
	}
	c := base
	c.OverlayListen = "127.0.0.1:8080"
	if err := c.Validate(); err != nil {
		t.Fatalf("loopback refused: %v", err)
	}
	c.OverlayListen, c.OverlayAllowAny = "0.0.0.0:8080", true
	if err := c.Validate(); err != nil {
		t.Fatalf("allow-any refused: %v", err)
	}
	c = base
	c.OverlayListen, c.IngestPublicHost = "127.0.0.1:8080", ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "EXCUBRA_INGEST_PUBLIC_HOST") {
		t.Fatalf("missing public host: %v", err)
	}
	c = base
	c.OverlayListen, c.IngestPublicHost = "127.0.0.1:8080", "ingest.example.test:8443"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if h, p := c.IngestHostPort(); h != "ingest.example.test" || p != "8443" {
		t.Fatalf("host/port: %s %s", h, p)
	}
}
