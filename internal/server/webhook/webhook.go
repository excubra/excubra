// Package webhook delivers events to CRM targets per contract v1 and ADR-0012:
// HMAC-SHA256 over timestamp + "." + body, at-least-once with exponential backoff
// up to 24 hours, byte-identical retries, delivery state beside the event.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/store"
)

// Header names from the contract.
const (
	HeaderEventID   = "X-EX0-Event-Id"
	HeaderTimestamp = "X-EX0-Timestamp"
	HeaderSignature = "X-EX0-Signature"
)

// MaxAge is how long a delivery is retried after the event occurred.
const MaxAge = 24 * time.Hour

// MaxSkew is how old a signature timestamp may be for a receiver to accept it.
const MaxSkew = 5 * time.Minute

// Sign returns the X-EX0-Signature value for a body sent at a unix timestamp.
func Sign(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify is the receiver side: signature must match and the timestamp must be
// within MaxSkew of now. Integrators can copy this function.
func Verify(secret, signature, timestampHeader string, body []byte, now time.Time) error {
	tsInt, err := strconv.ParseInt(strings.TrimSpace(timestampHeader), 10, 64)
	if err != nil {
		return errors.New("webhook: bad timestamp")
	}
	if d := now.Unix() - tsInt; d > int64(MaxSkew/time.Second) || d < -int64(MaxSkew/time.Second) {
		return errors.New("webhook: timestamp outside the allowed window")
	}
	if !hmac.Equal([]byte(Sign(secret, tsInt, body)), []byte(strings.TrimSpace(signature))) {
		return errors.New("webhook: signature mismatch")
	}
	return nil
}

// Backoff returns the delay before the next attempt after `attempts` failures:
// 30 s, 1 m, 2 m, 5 m, 10 m, 30 m, 1 h, then hourly.
func Backoff(attempts int) time.Duration {
	switch {
	case attempts <= 1:
		return 30 * time.Second
	case attempts == 2:
		return time.Minute
	case attempts == 3:
		return 2 * time.Minute
	case attempts == 4:
		return 5 * time.Minute
	case attempts == 5:
		return 10 * time.Minute
	case attempts == 6:
		return 30 * time.Minute
	default:
		return time.Hour
	}
}

// Deliverer publishes events (store + fan-out) and works off due deliveries.
type Deliverer struct {
	Store   *store.Store
	Client  *http.Client
	Version string
	Log     *slog.Logger
	// Link builds the console link for an event; nil means no link.
	Link func(ev event.Event) string
	// Now is overridable for tests.
	Now func() time.Time

	mu       sync.Mutex
	inFlight map[string]bool // target ids currently being delivered to
}

// New returns a deliverer with the contract's client settings: 10 s timeout, no
// redirects.
func New(st *store.Store, version string, log *slog.Logger) *Deliverer {
	if log == nil {
		log = slog.Default()
	}
	return &Deliverer{
		Store:   st,
		Version: version,
		Log:     log,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Now:      time.Now,
		inFlight: map[string]bool{},
	}
}

// Publish stores an event and creates one pending delivery per matching target.
// test.ping events go only to the target named in Details["target_id"].
func (d *Deliverer) Publish(ctx context.Context, ev event.Event) error {
	if ev.ID == "" || ev.TenantID == "" || !ev.Type.Valid() {
		return fmt.Errorf("webhook: refusing to publish incomplete event %+v", ev)
	}
	if d.Link != nil {
		ev.Link = d.Link(ev)
	}
	var targetIDs []string
	if ev.Type == event.TestPing {
		if tid, _ := ev.Details["target_id"].(string); tid != "" {
			targetIDs = []string{tid}
		}
	} else {
		targets, err := d.Store.TargetsForTenant(ctx, ev.TenantID)
		if err != nil {
			return err
		}
		for _, t := range targets {
			targetIDs = append(targetIDs, t.ID)
		}
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	return d.Store.InsertEvent(ctx, ev, body, targetIDs, d.Now())
}

// Run works off due deliveries every interval until ctx ends.
func (d *Deliverer) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := d.RunOnce(ctx); err != nil && ctx.Err() == nil {
			d.Log.Error("webhook worker", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce attempts every due delivery once, at most one in flight per target and
// eight overall. It returns how many attempts were made.
func (d *Deliverer) RunOnce(ctx context.Context) (int, error) {
	now := d.Now()
	due, err := d.Store.DueDeliveries(ctx, now, 64)
	if err != nil || len(due) == 0 {
		return 0, err
	}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	attempts := 0
	var amu sync.Mutex
	for _, dl := range due {
		if !d.claim(dl.TargetID) {
			continue // another attempt to this target is in flight; next tick
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(dl store.Delivery) {
			defer wg.Done()
			defer func() { <-sem }()
			defer d.release(dl.TargetID)
			d.attempt(ctx, dl, d.Now())
			amu.Lock()
			attempts++
			amu.Unlock()
		}(dl)
	}
	wg.Wait()
	return attempts, nil
}

func (d *Deliverer) claim(target string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inFlight[target] {
		return false
	}
	d.inFlight[target] = true
	return true
}

func (d *Deliverer) release(target string) {
	d.mu.Lock()
	delete(d.inFlight, target)
	d.mu.Unlock()
}

// attempt performs one delivery attempt and records the outcome.
func (d *Deliverer) attempt(ctx context.Context, dl store.Delivery, now time.Time) {
	target, err := d.Store.WebhookTarget(ctx, dl.TargetID)
	if err != nil || !target.Enabled {
		dl.State = store.DeliveryFailed
		dl.LastError = "target missing or disabled"
		dl.NextAttemptAt = now
		d.save(ctx, dl)
		return
	}
	status, attemptErr := d.send(ctx, target, dl, now)
	dl.Attempts++
	dl.LastStatus = status
	if attemptErr == nil {
		dl.State = store.DeliveryDelivered
		dl.LastError = ""
		dl.DeliveredAt = now
		d.save(ctx, dl)
		return
	}
	dl.LastError = truncate(attemptErr.Error(), 500)
	occurred := dl.CreatedAt
	if t, ok := id.TimeOf(dl.EventID); ok {
		occurred = t
	}
	next := now.Add(Backoff(dl.Attempts))
	if next.Sub(occurred) > MaxAge {
		dl.State = store.DeliveryFailed
		dl.NextAttemptAt = now
		d.Log.Warn("webhook delivery failed for good", "event", dl.EventID, "target", target.Name, "attempts", dl.Attempts, "err", dl.LastError)
	} else {
		dl.NextAttemptAt = next
	}
	d.save(ctx, dl)
}

func (d *Deliverer) send(ctx context.Context, target store.WebhookTarget, dl store.Delivery, now time.Time) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewReader([]byte(dl.Body)))
	if err != nil {
		return 0, err
	}
	ts := now.Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "excubra/"+d.Version)
	req.Header.Set(HeaderEventID, dl.EventID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, Sign(target.Secret, ts, []byte(dl.Body)))
	resp, err := d.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("http %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func (d *Deliverer) save(ctx context.Context, dl store.Delivery) {
	if err := d.Store.UpdateDelivery(ctx, dl); err != nil {
		d.Log.Error("webhook: saving delivery state", "event", dl.EventID, "target", dl.TargetID, "err", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
