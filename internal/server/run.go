package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/excubra/excubra/internal/agent/update"
	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/api"
	"github.com/excubra/excubra/internal/server/catalog"
	"github.com/excubra/excubra/internal/server/console"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/ingest"
	"github.com/excubra/excubra/internal/server/selfupdate"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/server/webhook"
	"github.com/excubra/excubra/internal/version"
)

// certProvider hands the current ingest certificate to the TLS stack and lets the
// renewal loop swap it without a restart.
type certProvider struct {
	cert atomic.Pointer[tls.Certificate]
}

func (p *certProvider) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := p.cert.Load()
	if c == nil {
		return nil, errors.New("no certificate")
	}
	return c, nil
}

func newLogger(cfg Config) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

// run starts both listeners, the ticker and the webhook worker, and stops them on
// SIGINT/SIGTERM.
func run(envFile string) error {
	cfg, err := LoadConfig(envFile, os.Getenv)
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	slog.SetDefault(log)
	log.Info("excubra server starting", "version", version.Version, "data", cfg.DataDir)

	// self-update (ADR-0006): a build that never confirmed its health is rolled back
	// before anything else runs; the roll-back itself ends in exit code 75
	upd, err := update.New(cfg.DataDir, log)
	if err != nil {
		return err
	}
	upd.Trial = serverTrial(envFile)
	if err := upd.RollbackIfStale(); err != nil {
		return err
	}
	rolledBack, wasRolledBack := upd.RolledBack()

	if err := waitForOverlayAddress(cfg, log); err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if wasRolledBack {
		log.Warn("self-update rolled back", "failed_version", rolledBack.To, "restored", rolledBack.From)
		_ = st.Audit(context.Background(), time.Now(), "server", "server.update.rolled_back", rolledBack.To, "restored "+rolledBack.From+": the new build did not confirm within 5 minutes")
	}

	caDir := filepath.Join(cfg.DataDir, "ca")
	ca, err := pki.LoadOrCreateCA(caDir)
	if err != nil {
		return err
	}
	ingestHost, _ := cfg.IngestHostPort()
	srvCert, err := ca.LoadOrCreateServerCert(caDir, ingestHost)
	if err != nil {
		return err
	}
	prov := &certProvider{}
	prov.cert.Store(&srvCert)
	log.Info("internal CA ready", "fingerprint", ca.Fingerprint(), "ingest_host", ingestHost)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	deliverer := webhook.New(st, version.Version, log)
	base := cfg.ConsoleBaseURL()
	deliverer.Link = func(ev event.Event) string {
		switch {
		case ev.HostID != "":
			return base + "/hosts/" + ev.HostID
		case ev.DeviceID != "":
			return base + "/devices/" + ev.DeviceID
		case ev.BoxID != "":
			return base + "/boxes/" + ev.BoxID
		}
		return base + "/tenants/" + ev.TenantID
	}
	eng, err := core.Load(ctx, st, deliverer, log)
	if err != nil {
		return err
	}

	ingestSrv := &http.Server{
		Addr:              cfg.IngestListen,
		Handler:           ingest.New(eng, st, ca, log).Handler(),
		TLSConfig:         pki.IngestTLSConfig(ca, prov.get),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		return err
	}
	ingestPort, _ := strconv.Atoi(func() string { _, p := cfg.IngestHostPort(); return p }())
	con, err := console.New(eng, st, ca, log, loc, ingestHost, ingestPort)
	if err != nil {
		return err
	}
	con.Secure = cfg.OverlayTLS == "internal"
	overlayMux := http.NewServeMux()
	overlayMux.Handle("/v1/", api.New(eng, st, log).Handler())
	overlayMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "ok %s\n", version.Version)
	})
	overlayMux.Handle("/", con.Handler())
	overlaySrv := &http.Server{
		Addr:              cfg.OverlayListen,
		Handler:           overlayMux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if cfg.OverlayTLS == "internal" {
		host, _, _ := net.SplitHostPort(cfg.OverlayListen)
		names := []string{host}
		// the console may also be reached by the name in EXCUBRA_CONSOLE_URL
		if u, err := url.Parse(cfg.ConsoleURL); err == nil && u.Hostname() != "" && u.Hostname() != host {
			names = append(names, u.Hostname())
		}
		oc, _, _, err := ca.IssueServerNames(names, pki.ServerCertValidity)
		if err != nil {
			return err
		}
		overlaySrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{oc}}
	}

	// bind first, serve second: a port that is taken fails now, and a freshly
	// installed build has proven itself once both listeners are up
	var lc net.ListenConfig
	ingestLn, err := lc.Listen(ctx, "tcp", cfg.IngestListen)
	if err != nil {
		return fmt.Errorf("ingest listener: %w", err)
	}
	overlayLn, err := lc.Listen(ctx, "tcp", cfg.OverlayListen)
	if err != nil {
		return fmt.Errorf("overlay listener: %w", err)
	}
	errc := make(chan error, 2)
	go func() {
		log.Info("ingest listening", "addr", cfg.IngestListen)
		errc <- ingestSrv.ServeTLS(ingestLn, "", "")
	}()
	go func() {
		log.Info("overlay listening", "addr", cfg.OverlayListen, "tls", cfg.OverlayTLS)
		if overlaySrv.TLSConfig != nil {
			errc <- overlaySrv.ServeTLS(overlayLn, "", "")
		} else {
			errc <- overlaySrv.Serve(overlayLn)
		}
	}()
	upd.Confirm()

	restartc := make(chan error, 1)
	su := selfupdate.New(st, upd, cfg.DataDir, runtime.GOOS, runtime.GOARCH, cfg.SelfUpdate == "on", log)
	if wasRolledBack {
		su.NoteRollback(rolledBack)
	}
	con.SelfUpdate = su
	if cfg.SelfUpdate == "on" {
		go func() {
			if err := su.Run(ctx); err != nil {
				restartc <- err
			}
		}()
	}
	go eng.RunTicker(ctx, 10*time.Second)
	if cfg.ReleaseCatalog != "" && cfg.ReleaseCatalog != "off" {
		// release metadata from the project's published releases, hourly (ADR-0006)
		cat := catalog.New(cfg.ReleaseCatalog, st, log)
		con.Catalog = cat
		go cat.Run(ctx, time.Hour)
	}
	go deliverer.Run(ctx, 5*time.Second)
	go renewLoop(ctx, ca, caDir, ingestHost, prov, log)
	if cfg.OverlayAllowAny {
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				log.Warn("EXCUBRA_OVERLAY_ALLOW_ANY is set: the console listener is not restricted to the overlay — development only")
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}

	var result error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			stop()
			return fmt.Errorf("listener: %w", err)
		}
	case err := <-restartc:
		// the self-update swapped the binary: drain, then exit 75 so systemd starts the new one
		log.Info("self-update installed, restarting")
		result = err
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = ingestSrv.Shutdown(shutdownCtx)
	_ = overlaySrv.Shutdown(shutdownCtx)
	return result
}

// serverTrial is the updater's trial run for a candidate server binary: it must
// start, read the configuration and see the data directory.
func serverTrial(envFile string) func(ctx context.Context, candidate string) error {
	return func(ctx context.Context, candidate string) error {
		ctx, cancel := context.WithTimeout(ctx, update.TrialTime)
		defer cancel()
		args := []string{"server", "selftest"}
		if envFile != "" {
			args = append(args, "--env-file", envFile)
		}
		out, err := exec.CommandContext(ctx, candidate, args...).CombinedOutput() //nolint:gosec // the candidate passed sha256 and signature checks
		if err != nil {
			return fmt.Errorf("selftest failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// renewLoop reissues the ingest certificate when it approaches expiry.
func renewLoop(ctx context.Context, ca *pki.CA, caDir, host string, prov *certProvider, log *slog.Logger) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c, err := ca.LoadOrCreateServerCert(caDir, host)
			if err != nil {
				log.Error("ingest certificate renewal", "err", err)
				continue
			}
			prov.cert.Store(&c)
		}
	}
}

// waitForOverlayAddress gives the overlay interface (NetBird's wt0) up to two
// minutes to appear after boot before giving up; a typo still fails, just later.
func waitForOverlayAddress(cfg Config, log *slog.Logger) error {
	var err error
	for i := 0; i < 60; i++ {
		if err = checkOverlayAddress(cfg); err == nil {
			return nil
		}
		if i == 0 {
			log.Warn("overlay address not up yet, waiting", "addr", cfg.OverlayListen)
		}
		time.Sleep(2 * time.Second)
	}
	return err
}

// checkOverlayAddress refuses to bind the console to an address that is not on a
// local interface (a typo would otherwise fail later or bind somewhere unexpected).
func checkOverlayAddress(cfg Config) error {
	if cfg.OverlayAllowAny {
		return nil
	}
	host, _, err := net.SplitHostPort(cfg.OverlayListen)
	if err != nil {
		return err
	}
	want := net.ParseIP(host)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(want) {
			return nil
		}
	}
	return fmt.Errorf("EXCUBRA_OVERLAY_LISTEN %s is not an address of a local interface (is NetBird up?)", cfg.OverlayListen)
}
