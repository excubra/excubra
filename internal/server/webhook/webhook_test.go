package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/server/store"
)

var t0 = time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)

func TestSignVerify(t *testing.T) {
	body := []byte(`{"event_id":"evt_1"}`)
	sig := Sign("secret", 1757000000, body)
	if sig[:7] != "sha256=" || len(sig) != 7+64 {
		t.Fatalf("signature format: %s", sig)
	}
	now := time.Unix(1757000000+60, 0)
	if err := Verify("secret", sig, "1757000000", body, now); err != nil {
		t.Fatal(err)
	}
	if err := Verify("other", sig, "1757000000", body, now); err == nil {
		t.Fatal("wrong secret verified")
	}
	if err := Verify("secret", sig, "1757000001", body, now); err == nil {
		t.Fatal("changed timestamp verified")
	}
	if err := Verify("secret", sig, "1757000000", []byte(`{}`), now); err == nil {
		t.Fatal("changed body verified")
	}
	if err := Verify("secret", sig, "1757000000", body, now.Add(10*time.Minute)); err == nil {
		t.Fatal("stale timestamp accepted")
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 30 * time.Minute, time.Hour, time.Hour, time.Hour}
	for i, w := range want {
		if got := Backoff(i + 1); got != w {
			t.Errorf("Backoff(%d) = %v, want %v", i+1, got, w)
		}
	}
}

type fixture struct {
	st    *store.Store
	d     *Deliverer
	now   time.Time
	calls atomic.Int32
	fail  atomic.Int32 // how many calls to fail with 503
	seen  chan *http.Request
	srv   *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := &fixture{st: st, now: t0, seen: make(chan *http.Request, 16)}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytesReader(body))
		select {
		case f.seen <- r:
		default: // nobody is reading in this test; never block the handler
		}
		if f.fail.Load() > 0 {
			f.fail.Add(-1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(f.srv.Close)
	ctx := context.Background()
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "A", CreatedAt: t0}))
	must(t, st.CreateWebhookTarget(ctx, store.WebhookTarget{ID: "tgt_crm", Name: "crm", URL: f.srv.URL, Secret: "ex0-test-secret", TenantScope: "*", Enabled: true, CreatedAt: t0}))
	must(t, st.CreateWebhookTarget(ctx, store.WebhookTarget{ID: "tgt_other", Name: "other", URL: f.srv.URL, Secret: "s", TenantScope: "ten_b", Enabled: true, CreatedAt: t0}))
	f.d = New(st, "test", nil)
	f.d.Now = func() time.Time { return f.now }
	f.d.Link = func(ev event.Event) string { return "https://console.test/hosts/" + ev.HostID }
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) publish(t *testing.T, typ event.Type) event.Event {
	t.Helper()
	ev := event.New(typ, f.now)
	ev.TenantID, ev.SiteID, ev.BoxID, ev.HostID, ev.Source = "ten_a", "site_a", "box_1", "host_fw", event.SourceState
	ev.Host = &event.HostRef{Name: "fw", IP: "10.0.0.1"}
	must(t, f.d.Publish(context.Background(), ev))
	return ev
}

func TestPublishAndDeliver(t *testing.T) {
	f := newFixture(t)
	ev := f.publish(t, event.HostDown)
	dls, _ := f.st.Deliveries(context.Background(), "ten_a", ev.ID)
	if len(dls) != 1 || dls[0].TargetID != "tgt_crm" { // tgt_other is scoped to ten_b
		t.Fatalf("deliveries: %+v", dls)
	}
	n, err := f.d.RunOnce(context.Background())
	must(t, err)
	if n != 1 {
		t.Fatalf("attempts = %d", n)
	}
	req := <-f.seen
	body, _ := io.ReadAll(req.Body)
	if req.Header.Get(HeaderEventID) != ev.ID || req.Header.Get("Content-Type") != "application/json" || req.Header.Get("User-Agent") != "excubra/test" {
		t.Fatalf("headers: %v", req.Header)
	}
	if err := Verify("ex0-test-secret", req.Header.Get(HeaderSignature), req.Header.Get(HeaderTimestamp), body, f.now); err != nil {
		t.Fatal(err)
	}
	if string(body) != dls[0].Body {
		t.Fatal("sent body differs from stored body")
	}
	dls, _ = f.st.Deliveries(context.Background(), "ten_a", ev.ID)
	if dls[0].State != store.DeliveryDelivered || dls[0].Attempts != 1 || dls[0].LastStatus != 202 {
		t.Fatalf("after delivery: %+v", dls[0])
	}
	if n, _ := f.d.RunOnce(context.Background()); n != 0 {
		t.Fatal("delivered event retried")
	}
}

func TestRetryWithBackoffAndIdenticalBody(t *testing.T) {
	f := newFixture(t)
	f.fail.Store(2)
	ev := f.publish(t, event.HostDown)
	f.d.RunOnce(context.Background())
	r1 := <-f.seen
	b1, _ := io.ReadAll(r1.Body)
	dls, _ := f.st.Deliveries(context.Background(), "ten_a", ev.ID)
	if dls[0].State != store.DeliveryPending || dls[0].Attempts != 1 || dls[0].LastStatus != 503 || !dls[0].NextAttemptAt.Equal(f.now.Add(30*time.Second)) {
		t.Fatalf("after first failure: %+v", dls[0])
	}
	if n, _ := f.d.RunOnce(context.Background()); n != 0 {
		t.Fatal("retried before backoff elapsed")
	}
	f.now = f.now.Add(30 * time.Second)
	f.d.RunOnce(context.Background())
	r2 := <-f.seen
	b2, _ := io.ReadAll(r2.Body)
	if string(b1) != string(b2) || r1.Header.Get(HeaderEventID) != r2.Header.Get(HeaderEventID) {
		t.Fatal("retry body or event id differs")
	}
	if r1.Header.Get(HeaderSignature) == r2.Header.Get(HeaderSignature) {
		t.Fatal("retry must carry a fresh timestamp and signature")
	}
	f.now = f.now.Add(time.Minute)
	f.d.RunOnce(context.Background())
	<-f.seen
	dls, _ = f.st.Deliveries(context.Background(), "ten_a", ev.ID)
	if dls[0].State != store.DeliveryDelivered || dls[0].Attempts != 3 {
		t.Fatalf("after success: %+v", dls[0])
	}
}

func TestGivesUpAfter24h(t *testing.T) {
	f := newFixture(t)
	f.fail.Store(1000)
	ev := f.publish(t, event.HostDown)
	for i := 0; i < 40; i++ {
		f.d.RunOnce(context.Background())
		dls, _ := f.st.Deliveries(context.Background(), "ten_a", ev.ID)
		if dls[0].State == store.DeliveryFailed {
			if f.now.Sub(t0) < 23*time.Hour {
				t.Fatalf("gave up too early after %v", f.now.Sub(t0))
			}
			return
		}
		f.now = dls[0].NextAttemptAt
	}
	t.Fatal("never gave up")
}

func TestTestPingGoesToOneTarget(t *testing.T) {
	f := newFixture(t)
	ev := event.New(event.TestPing, f.now)
	ev.TenantID, ev.Source = "ten_a", event.SourceConsole
	ev.Details = map[string]any{"target_id": "tgt_other", "triggered_by": "jeremia"}
	must(t, f.d.Publish(context.Background(), ev))
	dls, _ := f.st.Deliveries(context.Background(), "ten_a", ev.ID)
	if len(dls) != 1 || dls[0].TargetID != "tgt_other" {
		t.Fatalf("test ping deliveries: %+v", dls)
	}
}

func TestDisabledTargetFailsImmediately(t *testing.T) {
	f := newFixture(t)
	ev := f.publish(t, event.HostDown)
	tgt, _ := f.st.WebhookTarget(context.Background(), "tgt_crm")
	tgt.Enabled = false
	must(t, f.st.UpdateWebhookTarget(context.Background(), tgt))
	f.d.RunOnce(context.Background())
	dls, _ := f.st.Deliveries(context.Background(), "ten_a", ev.ID)
	if dls[0].State != store.DeliveryFailed || f.calls.Load() != 0 {
		t.Fatalf("disabled target: %+v calls=%d", dls[0], f.calls.Load())
	}
}

func TestPublishRejectsIncompleteEvents(t *testing.T) {
	f := newFixture(t)
	if err := f.d.Publish(context.Background(), event.Event{}); err == nil {
		t.Fatal("empty event published")
	}
}
