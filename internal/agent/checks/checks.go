// Package checks implements the closed set of host checks (ADR-0007): icmp, tcp and
// http. There is no other kind of probe in the agent, and the server cannot ask for
// one — Runner refuses anything not in this file.
package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// Timeouts per check. A round of checks must finish well inside one check interval.
const (
	Timeout     = 5 * time.Second
	Parallelism = 32 // upper bound on concurrent checks, so a big site cannot swamp a Pi
)

// ErrUnsupportedType is returned for a check type this build does not implement.
var ErrUnsupportedType = errors.New("checks: unsupported check type")

// Pinger performs an ICMP echo. It is an interface so that hosts without raw
// sockets (macOS during development, tests) can supply a fake.
type Pinger interface {
	Ping(ctx context.Context, address string) (time.Duration, error)
}

// Runner executes rounds of checks for hosts.
type Runner struct {
	Pinger Pinger
	// HTTPClient is used for http checks; nil means a client that does not follow
	// redirects and does not read the body.
	HTTPClient *http.Client
	// Now is overridable for tests.
	Now func() time.Time
}

// NewRunner returns a runner with the default HTTP client. The client deliberately
// does not verify TLS: an http check asks "does this answer", not "is the
// certificate valid" — devices in a LAN carry self-signed certificates.
func NewRunner(p Pinger) *Runner {
	return &Runner{
		Pinger: p,
		HTTPClient: &http.Client{
			Timeout:       Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				TLSClientConfig:     insecureTLS(),
				DisableKeepAlives:   true,
				TLSHandshakeTimeout: Timeout,
			},
		},
		Now: time.Now,
	}
}

// Round runs every check of one host once and reports the combined result. A round
// is ok only when every check is ok (ADR-0003).
func (r *Runner) Round(ctx context.Context, host wire.HostConfig) wire.Round {
	now := r.Now
	if now == nil {
		now = time.Now
	}
	round := wire.Round{At: now().UTC(), OK: true}
	if len(host.Checks) == 0 {
		round.OK = false
		round.Checks = []wire.CheckResult{{Type: "none", OK: false, Error: "host has no checks configured"}}
		return round
	}
	results := make([]wire.CheckResult, len(host.Checks))
	var wg sync.WaitGroup
	for i, c := range host.Checks {
		wg.Add(1)
		go func(i int, c wire.CheckConfig) {
			defer wg.Done()
			results[i] = r.one(ctx, host.Address, c)
		}(i, c)
	}
	wg.Wait()
	for _, res := range results {
		if !res.OK {
			round.OK = false
		}
	}
	round.Checks = results
	return round
}

// one executes a single check. The type switch is the closed list.
func (r *Runner) one(ctx context.Context, address string, c wire.CheckConfig) wire.CheckResult {
	res := wire.CheckResult{Type: c.Label()}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	switch c.Type {
	case wire.CheckICMP:
		if r.Pinger == nil {
			res.Error = "icmp not available on this build"
			return res
		}
		d, err := r.Pinger.Ping(ctx, address)
		if err != nil {
			res.Error = short(err)
			return res
		}
		res.OK, res.LatencyMS = true, ms(d)
		return res

	case wire.CheckTCP:
		if c.Port < 1 || c.Port > 65535 {
			res.Error = "port out of range"
			return res
		}
		start := time.Now()
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(address, fmt.Sprint(c.Port)))
		if err != nil {
			res.Error = short(err)
			return res
		}
		_ = conn.Close()
		res.OK, res.LatencyMS = true, ms(time.Since(start))
		return res

	case wire.CheckHTTP:
		url := c.URL
		if url == "" {
			res.Error = "no url configured"
			return res
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			res.Error = short(err)
			return res
		}
		req.Header.Set("User-Agent", "excubra-agent")
		start := time.Now()
		resp, err := r.HTTPClient.Do(req)
		if err != nil {
			res.Error = short(err)
			return res
		}
		_ = resp.Body.Close() // the body is never read, let alone stored
		res.Status, res.LatencyMS = resp.StatusCode, ms(time.Since(start))
		lo, hi := 200, 399
		if len(c.ExpectStatus) == 2 {
			lo, hi = c.ExpectStatus[0], c.ExpectStatus[1]
		} else if len(c.ExpectStatus) == 1 {
			lo, hi = c.ExpectStatus[0], c.ExpectStatus[0]
		}
		if resp.StatusCode < lo || resp.StatusCode > hi {
			res.Error = fmt.Sprintf("status %d outside %d..%d", resp.StatusCode, lo, hi)
			return res
		}
		res.OK = true
		return res

	default:
		res.Error = "unsupported check type"
		return res
	}
}

// Validate reports which configured checks this agent cannot run, for the
// config_errors field of the heartbeat (ADR-0003).
func Validate(hosts []wire.HostConfig) []string {
	var errs []string
	for _, h := range hosts {
		for _, c := range h.Checks {
			switch c.Type {
			case wire.CheckICMP:
			case wire.CheckTCP:
				if c.Port < 1 || c.Port > 65535 {
					errs = append(errs, fmt.Sprintf("host %s: tcp check without a valid port", h.HostID))
				}
			case wire.CheckHTTP:
				if c.URL == "" {
					errs = append(errs, fmt.Sprintf("host %s: http check without a url", h.HostID))
				}
			default:
				errs = append(errs, fmt.Sprintf("host %s: unknown check type %q", h.HostID, c.Type))
			}
		}
	}
	return errs
}

func ms(d time.Duration) *int64 {
	v := d.Milliseconds()
	return &v
}

// short turns a network error into something that fits in an event without leaking
// the whole dial string.
func short(err error) string {
	s := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"):
		return "timeout"
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "no route to host"):
		return "no route to host"
	case strings.Contains(s, "network is unreachable"):
		return "network unreachable"
	case strings.Contains(s, "no such host"):
		return "name does not resolve"
	case strings.Contains(s, "certificate"):
		return "tls error"
	}
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 60 {
		return s[i+2:]
	}
	if len(s) > 80 {
		return s[:80]
	}
	return s
}
