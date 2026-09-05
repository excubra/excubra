package server

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Config is everything the server reads from the environment (ADR-0009). All other
// settings are data in the store, edited in the console.
type Config struct {
	DataDir          string
	IngestListen     string
	IngestPublicHost string // host[:port] boxes connect to; goes into enrollment keys and the ingest certificate
	OverlayListen    string // ip:port, never a wildcard
	OverlayAllowAny  bool   // development only
	OverlayTLS       string // off | internal
	ConsoleURL       string // base URL for webhook links; derived from OverlayListen when empty
	UpdateBaseURL    string
	LogLevel         string
	LogFormat        string
	Timezone         string // IANA name used by the console for display; storage stays UTC
}

// DefaultEnvFile is read when it exists and no --env-file was given.
const DefaultEnvFile = "/etc/excubra/server.env"

// LoadConfig builds the configuration from an optional env file and the process
// environment; the environment wins over the file.
func LoadConfig(envFile string, getenv func(string) string) (Config, error) {
	values := map[string]string{}
	path := envFile
	if path == "" {
		if _, err := os.Stat(DefaultEnvFile); err == nil {
			path = DefaultEnvFile
		}
	}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: %w", err)
		}
		values, err = ParseEnvFile(f)
		_ = f.Close()
		if err != nil {
			return Config{}, fmt.Errorf("config: %s: %w", path, err)
		}
	}
	get := func(key, def string) string {
		if v := getenv(key); v != "" {
			return v
		}
		if v, ok := values[key]; ok && v != "" {
			return v
		}
		return def
	}
	c := Config{
		DataDir:          get("EXCUBRA_DATA_DIR", "/var/lib/excubra"),
		IngestListen:     get("EXCUBRA_INGEST_LISTEN", ":443"),
		IngestPublicHost: get("EXCUBRA_INGEST_PUBLIC_HOST", ""),
		OverlayListen:    get("EXCUBRA_OVERLAY_LISTEN", ""),
		OverlayAllowAny:  get("EXCUBRA_OVERLAY_ALLOW_ANY", "") == "1",
		OverlayTLS:       get("EXCUBRA_OVERLAY_TLS", "off"),
		ConsoleURL:       get("EXCUBRA_CONSOLE_URL", ""),
		UpdateBaseURL:    get("EXCUBRA_UPDATE_BASE_URL", "https://github.com/excubra/excubra/releases/download"),
		LogLevel:         get("EXCUBRA_LOG_LEVEL", "info"),
		LogFormat:        get("EXCUBRA_LOG_FORMAT", "text"),
		Timezone:         get("EXCUBRA_TIMEZONE", "Europe/Berlin"),
	}
	return c, c.Validate()
}

// ParseEnvFile reads KEY=value lines (systemd EnvironmentFile style): blank lines
// and # comments are skipped, an optional "export " prefix and surrounding single
// or double quotes are stripped.
func ParseEnvFile(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		s = strings.TrimPrefix(s, "export ")
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected KEY=value", line)
		}
		k = strings.TrimSpace(k)
		if k == "" || strings.ContainsAny(k, " \t") {
			return nil, fmt.Errorf("line %d: bad key", line)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Validate refuses configurations that would expose the console or cannot work.
func (c Config) Validate() error {
	var errs []error
	if c.IngestPublicHost == "" {
		errs = append(errs, errors.New("EXCUBRA_INGEST_PUBLIC_HOST is required (host[:port] the boxes connect to)"))
	} else if h, _, err := splitHostPortDefault(c.IngestPublicHost, "443"); err != nil || h == "" {
		errs = append(errs, fmt.Errorf("EXCUBRA_INGEST_PUBLIC_HOST %q is not host[:port]", c.IngestPublicHost))
	}
	if _, _, err := net.SplitHostPort(c.IngestListen); err != nil {
		errs = append(errs, fmt.Errorf("EXCUBRA_INGEST_LISTEN %q is not [host]:port", c.IngestListen))
	}
	if c.OverlayListen == "" {
		errs = append(errs, errors.New("EXCUBRA_OVERLAY_LISTEN is required (ip:port on the NetBird interface)"))
	} else {
		host, _, err := net.SplitHostPort(c.OverlayListen)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("EXCUBRA_OVERLAY_LISTEN %q is not ip:port", c.OverlayListen))
		case !c.OverlayAllowAny && (host == "" || host == "0.0.0.0" || host == "::" || net.ParseIP(host) == nil):
			errs = append(errs, fmt.Errorf("EXCUBRA_OVERLAY_LISTEN %q must be a specific IP address, never a wildcard or a name (set EXCUBRA_OVERLAY_ALLOW_ANY=1 for development only)", c.OverlayListen))
		}
	}
	switch c.OverlayTLS {
	case "off", "internal":
	default:
		errs = append(errs, fmt.Errorf("EXCUBRA_OVERLAY_TLS %q must be off or internal", c.OverlayTLS))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("EXCUBRA_LOG_LEVEL %q must be debug, info, warn or error", c.LogLevel))
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		errs = append(errs, fmt.Errorf("EXCUBRA_LOG_FORMAT %q must be text or json", c.LogFormat))
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		errs = append(errs, fmt.Errorf("EXCUBRA_TIMEZONE %q is not a known IANA zone", c.Timezone))
	}
	return errors.Join(errs...)
}

// IngestHostPort splits the public host into host and port (default 443).
func (c Config) IngestHostPort() (string, string) {
	h, p, err := splitHostPortDefault(c.IngestPublicHost, "443")
	if err != nil {
		return c.IngestPublicHost, "443"
	}
	return h, p
}

// ConsoleBaseURL returns the base URL used in webhook links.
func (c Config) ConsoleBaseURL() string {
	if c.ConsoleURL != "" {
		return strings.TrimRight(c.ConsoleURL, "/")
	}
	scheme := "http"
	if c.OverlayTLS == "internal" {
		scheme = "https"
	}
	return scheme + "://" + c.OverlayListen
}

func splitHostPortDefault(s, defPort string) (string, string, error) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p, nil
	}
	if strings.Contains(s, ":") && !strings.HasPrefix(s, "[") {
		return "", "", fmt.Errorf("ambiguous host %q", s)
	}
	return strings.Trim(s, "[]"), defPort, nil
}
