// Package connect reads customer devices through their APIs from the box (ADR-0015).
// A Reader knows one device kind; the Runner keeps one loop per configured
// connector, opens the sealed credential with the box key, and hands the latest
// reading to the heartbeat. Reading only: nothing in this package changes a device.
package connect

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// Timing bounds for one connector loop.
const (
	minInterval     = time.Minute
	maxInterval     = time.Hour
	defaultInterval = 5 * time.Minute
	firstReadAfter  = 2 * time.Second
	readTimeout     = 30 * time.Second
)

// ErrAuth says the device refused the credential.
var ErrAuth = errors.New("device refused the credential")

// Target is what a Reader gets: where, with what, and how.
type Target struct {
	URL    string
	Secret []byte // the sealed JSON document, opened
	Client *http.Client
	// State is the reader's memory between reads of the same connector (log
	// cursors); the runner keeps it per connector and drops it on removal.
	State map[string]string
	Now   time.Time
}

// Reading is what a Reader returns.
type Reading struct {
	Facts   map[string]any     // what the device says about itself
	Metrics map[string]float64 // numbers worth charting
	Signals []wire.Signal      // what the device's logs say happened since the last read (ADR-0018 §7)
	// NewToken is set when the reader turned a one-time admin login into a credential
	// of its own (the credential document to use from now on). The runner seals it to
	// the box key and reports it; the server stores it and drops the admin login.
	NewToken []byte
}

// Reader reads one kind of device.
type Reader interface {
	Read(ctx context.Context, t Target) (Reading, error)
}

// readers is the closed registry; a new kind is a new file and an ADR line.
var readers = map[string]Reader{
	wire.ConnectorFortiGate: fortigate{},
	wire.ConnectorStarface:  starface{},
}

// Runner runs the configured connectors.
type Runner struct {
	Log  *slog.Logger
	Open func(sealed string) ([]byte, error) // opens a sealed credential with the box key
	Seal func(plain []byte) (string, error)  // seals to the box's own key (bootstrap results)
	Now  func() time.Time
	// OnSignals takes what a device's logs said (the sentinel queues it for the heartbeat).
	OnSignals func([]wire.Signal)

	mu        sync.Mutex
	ctx       context.Context
	loops     map[string]*loop
	latest    map[string]wire.ConnectorReport
	sentFacts map[string]string            // connector id → hash of the facts the server acknowledged
	pending   map[string]string            // connector id → hash handed out in the last Reports()
	override  map[string][]byte            // connector id → credential from a bootstrap, until the server has it
	overVer   map[string]string            // connector id → config version the override belongs to
	tokenSent map[string]bool              // connector id → the sealed token went out and was acknowledged
	state     map[string]map[string]string // connector id → the reader's memory between reads
}

type loop struct {
	cfg    wire.ConnectorConfig
	cancel context.CancelFunc
}

// New returns a runner; Run must be called before loops start.
func New(log *slog.Logger, open func(string) ([]byte, error)) *Runner {
	if log == nil {
		log = slog.Default()
	}
	return &Runner{Log: log, Open: open, Now: time.Now, loops: map[string]*loop{}, latest: map[string]wire.ConnectorReport{}, sentFacts: map[string]string{}, pending: map[string]string{},
		override: map[string][]byte{}, overVer: map[string]string{}, tokenSent: map[string]bool{}, state: map[string]map[string]string{}}
}

// Run starts the loops of every applied connector and blocks until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	r.mu.Lock()
	r.ctx = ctx
	for _, l := range r.loops {
		r.startLocked(l)
	}
	r.mu.Unlock()
	<-ctx.Done()
}

// Apply installs the connector list: unchanged ones keep running, changed ones
// restart, missing ones stop and forget their reading.
func (r *Runner) Apply(cfgs []wire.ConnectorConfig) {
	if len(cfgs) > wire.MaxConnectors {
		cfgs = cfgs[:wire.MaxConnectors]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	keep := map[string]bool{}
	for _, cfg := range cfgs {
		if cfg.ID == "" {
			continue
		}
		keep[cfg.ID] = true
		if v, ok := r.overVer[cfg.ID]; ok && v != cfg.Version {
			// the server's new document wins: forget what the bootstrap produced
			delete(r.override, cfg.ID)
			delete(r.overVer, cfg.ID)
			delete(r.tokenSent, cfg.ID)
		}
		if l, ok := r.loops[cfg.ID]; ok {
			if l.cfg.Version == cfg.Version {
				continue
			}
			if l.cancel != nil {
				l.cancel()
			}
		}
		l := &loop{cfg: cfg}
		r.loops[cfg.ID] = l
		if r.ctx != nil {
			r.startLocked(l)
		}
	}
	for id, l := range r.loops {
		if !keep[id] {
			if l.cancel != nil {
				l.cancel()
			}
			delete(r.loops, id)
			delete(r.latest, id)
			delete(r.sentFacts, id)
			delete(r.state, id)
			delete(r.pending, id)
			delete(r.override, id)
			delete(r.overVer, id)
			delete(r.tokenSent, id)
		}
	}
}

func (r *Runner) startLocked(l *loop) {
	ctx, cancel := context.WithCancel(r.ctx)
	l.cancel = cancel
	go r.loop(ctx, l.cfg)
}

func (r *Runner) loop(ctx context.Context, cfg wire.ConnectorConfig) {
	every := time.Duration(cfg.IntervalS) * time.Second
	switch {
	case every <= 0:
		every = defaultInterval
	case every < minInterval:
		every = minInterval
	case every > maxInterval:
		every = maxInterval
	}
	t := time.NewTimer(firstReadAfter)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r.ReadOnce(ctx, cfg)
		t.Reset(every)
	}
}

// ReadOnce reads one connector now and records the result.
func (r *Runner) ReadOnce(ctx context.Context, cfg wire.ConnectorConfig) {
	rep := wire.ConnectorReport{ID: cfg.ID, DeviceID: cfg.DeviceID, Kind: cfg.Kind, CollectedAt: r.Now().UTC()}
	reading, fp, err := r.read(ctx, cfg)
	rep.TLSFingerprint = fp
	if err != nil {
		rep.Error = err.Error()
		r.Log.Warn("connector", "kind", cfg.Kind, "device", cfg.DeviceID, "err", err)
	} else {
		rep.OK = true
		rep.Metrics = reading.Metrics
		if len(reading.Signals) > 0 && r.OnSignals != nil {
			for i := range reading.Signals {
				reading.Signals[i].DeviceID = cfg.DeviceID
			}
			r.OnSignals(reading.Signals)
		}
		if len(reading.NewToken) > 0 && r.Seal != nil {
			// use the new credential from now on and hand it to the server, sealed
			r.mu.Lock()
			r.override[cfg.ID] = reading.NewToken
			r.overVer[cfg.ID] = cfg.Version
			r.mu.Unlock()
			if sealed, err := r.Seal(reading.NewToken); err == nil {
				rep.TokenSealed = sealed
			} else {
				r.Log.Error("sealing the new credential", "err", err)
			}
		}
		if b, err := json.Marshal(reading.Facts); err == nil {
			if len(b) > wire.MaxConnectorFactsSize {
				b, _ = json.Marshal(map[string]any{"_truncated": true, "_size": len(b)})
			}
			rep.Facts = b
		}
	}
	r.mu.Lock()
	r.latest[cfg.ID] = rep
	r.mu.Unlock()
}

func (r *Runner) read(ctx context.Context, cfg wire.ConnectorConfig) (Reading, string, error) {
	reader, ok := readers[cfg.Kind]
	if !ok {
		return Reading{}, "", fmt.Errorf("unknown connector kind %q", cfg.Kind)
	}
	if r.Open == nil {
		return Reading{}, "", errors.New("no seal key on this box")
	}
	r.mu.Lock()
	secret, overridden := r.override[cfg.ID]
	r.mu.Unlock()
	if !overridden {
		var err error
		if secret, err = r.Open(cfg.Sealed); err != nil {
			return Reading{}, "", fmt.Errorf("credential cannot be opened on this box: %w", err)
		}
	}
	var seen fingerprint
	client := &http.Client{Timeout: readTimeout, Transport: transport(cfg.TLSFingerprint, &seen)}
	cctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	r.mu.Lock()
	state := r.state[cfg.ID]
	if state == nil {
		state = map[string]string{}
		r.state[cfg.ID] = state
	}
	r.mu.Unlock()
	reading, err := reader.Read(cctx, Target{URL: cfg.URL, Secret: secret, Client: client, State: state, Now: r.Now()})
	return reading, seen.get(), err
}

// Reports returns the latest reading of every connector for a heartbeat. Facts are
// included only when they differ from what the server acknowledged; Ack or Nack
// must follow.
func (r *Runner) Reports() []wire.ConnectorReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []wire.ConnectorReport
	for id, rep := range r.latest {
		if rep.TokenSealed != "" && r.tokenSent[id] {
			rep.TokenSealed = ""
		}
		if rep.Facts != nil {
			h := hashOf(rep.Facts)
			if h == r.sentFacts[id] {
				rep.Facts = nil
			} else {
				r.pending[id] = h
			}
		}
		out = append(out, rep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Ack records that the last Reports() reached the server.
func (r *Runner) Ack() {
	r.mu.Lock()
	for id, h := range r.pending {
		r.sentFacts[id] = h
	}
	r.pending = map[string]string{}
	for id, rep := range r.latest {
		if rep.TokenSealed != "" {
			r.tokenSent[id] = true
		}
	}
	r.mu.Unlock()
}

// Nack forgets the last hand-out; the facts go again next time.
func (r *Runner) Nack() {
	r.mu.Lock()
	r.pending = map[string]string{}
	r.mu.Unlock()
}

// Latest returns the current reading of one connector (tests and diagnostics).
func (r *Runner) Latest(id string) (wire.ConnectorReport, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rep, ok := r.latest[id]
	return rep, ok
}

func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// fingerprint records the certificate a device presented.
type fingerprint struct {
	mu sync.Mutex
	v  string
}

func (f *fingerprint) set(v string) { f.mu.Lock(); f.v = v; f.mu.Unlock() }
func (f *fingerprint) get() string  { f.mu.Lock(); defer f.mu.Unlock(); return f.v }

// transport accepts the device's (usually self-signed) certificate, records its
// fingerprint, and refuses a different one when a pin is configured.
func transport(pin string, seen *fingerprint) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // devices use self-signed certificates; VerifyConnection pins the fingerprint instead
			MinVersion:         tls.VersionTLS12,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("device presented no certificate")
				}
				fp := certFingerprint(cs.PeerCertificates[0])
				seen.set(fp)
				if pin != "" && pin != fp {
					return fmt.Errorf("device certificate changed: expected %s, got %s", pin, fp)
				}
				return nil
			},
		},
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

func certFingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}

// getJSON is the one HTTP helper the readers share: GET, decode, sane errors.
func getJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrAuth
	case resp.StatusCode >= 300:
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Path)
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 4<<20))
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%s: %w", req.URL.Path, err)
	}
	return nil
}
