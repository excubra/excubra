package webhook

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/event"
)

var update = flag.Bool("update", false, "rewrite fixtures/events from the code")

// Fixture constants — documented in fixtures/events/README.md.
const (
	fixtureSecret    = "ex0-test-secret"
	fixtureTimestamp = int64(1757000000)
)

func fixtureID(n int) string { return fmt.Sprintf("evt_01k4c0ffee%016d", n) }

func tp(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	t = t.UTC()
	return &t
}

// sampleEvents is one complete, deterministic webhook body per event type.
func sampleEvents() []event.Event {
	host := &event.HostRef{Name: "FortiGate 60F", IP: "192.168.1.1", MAC: "00:09:0f:aa:bb:cc", Vendor: "Fortinet"}
	base := func(n int, t event.Type, at string) event.Event {
		ev := event.Event{ID: fixtureID(n), Type: t, Severity: t.DefaultSeverity(), OccurredAt: *tp(at), ReceivedAt: *tp(at),
			TenantID: "ten_kundea", SiteID: "site_ludwigshafen", BoxID: "box_0042", Source: event.SourceState}
		return ev
	}
	var evs []event.Event

	ev := base(1, event.BoxSilent, "2026-09-04T09:41:30Z")
	ev.Since = tp("2026-09-04T09:38:00Z")
	ev.Details = map[string]any{"missed_heartbeats": 3, "last_heartbeat_at": *tp("2026-09-04T09:38:00Z")}
	ev.Link = "https://ex0.viico.internal/boxes/box_0042"
	evs = append(evs, ev)

	ev = base(2, event.BoxBack, "2026-09-04T09:52:10Z")
	ev.Since = tp("2026-09-04T09:38:00Z")
	ev.Details = map[string]any{"silent_for_s": 850, "agent_version": "0.1.0"}
	ev.Link = "https://ex0.viico.internal/boxes/box_0042"
	evs = append(evs, ev)

	ev = base(3, event.HostDown, "2026-09-04T09:41:00Z")
	ev.HostID, ev.Host = "host_fortigate", host
	ev.Since = tp("2026-09-04T09:38:00Z")
	ev.Details = map[string]any{"checks_failed": []string{"icmp", "tcp:443"}, "consecutive_failures": 3, "box_time": *tp("2026-09-04T09:40:58Z")}
	ev.Link = "https://ex0.viico.internal/hosts/host_fortigate"
	evs = append(evs, ev)

	ev = base(4, event.HostUp, "2026-09-04T09:47:00Z")
	ev.HostID, ev.Host = "host_fortigate", host
	ev.Since = tp("2026-09-04T09:46:00Z")
	ev.Details = map[string]any{"down_for_s": 480, "consecutive_successes": 2, "box_time": *tp("2026-09-04T09:46:58Z")}
	ev.Link = "https://ex0.viico.internal/hosts/host_fortigate"
	evs = append(evs, ev)

	ev = base(5, event.DeviceNew, "2026-09-04T10:15:00Z")
	ev.Source, ev.DeviceID = event.SourceDiscovery, "dev_7m2x9q4t8r3w"
	ev.Since = tp("2026-09-04T10:15:00Z")
	ev.Device = &event.DeviceRef{IP: "192.168.1.77", MAC: "3c:2a:f4:11:22:33", Vendor: "Brother Industries", Hostname: "BRW3C2AF4112233", FirstSeen: tp("2026-09-04T10:15:00Z")}
	ev.Link = "https://ex0.viico.internal/devices/dev_7m2x9q4t8r3w"
	evs = append(evs, ev)

	ev = base(6, event.DeviceGone, "2026-09-05T10:20:00Z")
	ev.Source, ev.DeviceID = event.SourceDiscovery, "dev_7m2x9q4t8r3w"
	ev.Since = tp("2026-09-04T10:15:00Z")
	ev.Device = &event.DeviceRef{IP: "192.168.1.77", MAC: "3c:2a:f4:11:22:33", Vendor: "Brother Industries", Hostname: "BRW3C2AF4112233", LastSeen: tp("2026-09-04T10:15:00Z")}
	ev.Link = "https://ex0.viico.internal/devices/dev_7m2x9q4t8r3w"
	evs = append(evs, ev)

	ev = base(7, event.MaintenanceStarted, "2026-09-04T18:00:00Z")
	ev.Source, ev.HostID, ev.Host = event.SourceMaintenance, "host_fortigate", host
	ev.Maintenance = &event.MaintenanceRef{Scope: "host", Until: tp("2026-09-04T20:00:00Z"), Reason: "firmware update", SetBy: "jeremia"}
	ev.Link = "https://ex0.viico.internal/hosts/host_fortigate"
	evs = append(evs, ev)

	ev = base(8, event.MaintenanceEnded, "2026-09-04T20:00:00Z")
	ev.Source, ev.HostID = event.SourceMaintenance, "host_fortigate"
	ev.Maintenance = &event.MaintenanceRef{Scope: "host", Reason: "firmware update", Ended: "expired"}
	ev.Link = "https://ex0.viico.internal/hosts/host_fortigate"
	evs = append(evs, ev)

	ev = base(9, event.TestPing, "2026-09-04T08:00:00Z")
	ev.Source, ev.SiteID, ev.BoxID = event.SourceConsole, "", ""
	ev.Details = map[string]any{"target_id": "tgt_crm", "triggered_by": "jeremia"}
	evs = append(evs, ev)

	return evs
}

// TestFixtures keeps fixtures/events in sync with the code: with -update it
// rewrites them, otherwise it fails when they drifted.
func TestFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "fixtures", "events")
	var readme strings.Builder
	readme.WriteString("# Webhook fixtures (contract v1)\n\n")
	readme.WriteString("One complete webhook body per event type, generated from the code by\n`make fixtures`. Build your receiver against these before the first real event.\n\n")
	readme.WriteString("Every delivery carries three headers:\n\n")
	readme.WriteString("- `X-EX0-Event-Id` — the `event_id` of the body, stable across retries; deduplicate on it\n")
	readme.WriteString("- `X-EX0-Timestamp` — unix seconds of *this attempt*; reject if more than 5 minutes off\n")
	readme.WriteString("- `X-EX0-Signature` — `sha256=<hex>` of HMAC-SHA256(secret, timestamp + \".\" + body)\n\n")
	readme.WriteString("The body bytes are exactly the file contents (including the trailing newline).\n")
	fmt.Fprintf(&readme, "Signatures below use the test secret `%s` and the timestamp `%d`.\n", fixtureSecret, fixtureTimestamp)
	readme.WriteString("Retries resend byte-identical bodies with a fresh timestamp and signature.\n")
	readme.WriteString("Answer `2xx` at once and process asynchronously; anything else is retried with\n")
	readme.WriteString("backoff for 24 hours.\n\n")
	readme.WriteString("| File | Type | Severity | Signature |\n| --- | --- | --- | --- |\n")

	evs := sampleEvents()
	sort.Slice(evs, func(i, j int) bool { return evs[i].ID < evs[j].ID })
	files := map[string][]byte{}
	for _, ev := range evs {
		body, err := json.MarshalIndent(ev, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, '\n')
		name := string(ev.Type) + ".json"
		files[name] = body
		fmt.Fprintf(&readme, "| `%s` | `%s` | %s | `%s` |\n", name, ev.Type, ev.Severity, Sign(fixtureSecret, fixtureTimestamp, body))
	}
	readme.WriteString("\nVerification in Go (copy it):\n\n```go\nmac := hmac.New(sha256.New, []byte(secret))\nmac.Write([]byte(timestampHeader + \".\"))\nmac.Write(body)\nwant := \"sha256=\" + hex.EncodeToString(mac.Sum(nil))\nok := hmac.Equal([]byte(want), []byte(signatureHeader))\n```\n")
	files["README.md"] = []byte(readme.String())

	if *update {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, b := range files {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v (run `make fixtures`)", name, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s drifted from the code (run `make fixtures`)", name)
		}
	}
}
