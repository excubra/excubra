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

// Der Zuhörer im eigenen Netz ist genau dafür da: das eigene Netz. Eine
// öffentliche Adresse hier wäre die API im Internet — und das ist das eine,
// was dieser Zuhörer nie sein darf.
func TestTheLANListenerStaysInTheBuilding(t *testing.T) {
	base := func(lan string) Config {
		return Config{
			IngestPublicHost: "ingest.example.test",
			IngestListen:     ":443",
			OverlayListen:    "100.64.0.5:8080",
			OverlayTLS:       "off",
			SelfUpdate:       "on",
			LogLevel:         "info",
			LogFormat:        "text",
			LANListen:        lan,
		}
	}
	for _, c := range []struct {
		lan string
		ok  bool
	}{
		{"", true},                  // keiner ist die Vorgabe
		{"10.100.10.2:8080", true},  // das private Netz zwischen zwei eigenen Maschinen
		{"192.168.1.5:8080", true},  //
		{"127.0.0.1:8080", true},    // die eigene Maschine
		{"0.0.0.0:8080", false},     // ein Platzhalter ist keine Adresse
		{":8080", false},            //
		{"203.0.113.9:8080", false}, // öffentlich — genau das nicht
		{"ex0.intern:8080", false},  // ein Name, keine Adresse
		{"10.100.10.2", false},      // ohne Port
	} {
		err := base(c.lan).Validate()
		if (err == nil) != c.ok {
			t.Errorf("EXCUBRA_LAN_LISTEN=%q: %v, erwartet ok=%v", c.lan, err, c.ok)
		}
	}
	// Und nicht dieselbe Adresse wie der Overlay-Zuhörer: Ein Port kann nur
	// einmal vergeben werden, und der Fehler dabei käme erst beim Starten.
	cfg := base("100.64.0.5:8080")
	if err := cfg.Validate(); err == nil {
		t.Error("dieselbe Adresse zweimal wurde angenommen")
	}
}
