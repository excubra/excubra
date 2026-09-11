package console_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// seedDownHost creates a tenant, a site, an assigned box and one host that has just
// failed three rounds, so the overview has exactly one problem.
func seedDownHost(t *testing.T, f *fixture) store.Box {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	must(t, f.st.CreateTenant(ctx, store.Tenant{ID: "ten_x", Name: "X GmbH", CreatedAt: now}))
	must(t, f.eng.CreateSite(ctx, store.Site{ID: "site_x", TenantID: "ten_x", Name: "Werk", CreatedAt: now}, "test"))
	must(t, f.st.CreateBox(ctx, store.Box{ID: "box_x", HWID: "hw", CertSerial: "1", CertNotAfter: now.Add(time.Hour), EnrolledAt: now}))
	f.eng.RegisterBox(store.Box{ID: "box_x"})
	must(t, f.eng.AssignBox(ctx, "box_x", "site_x", "test"))
	must(t, f.eng.CreateHost(ctx, store.Host{ID: "host_x", TenantID: "ten_x", SiteID: "site_x", BoxID: "box_x", Name: "Firewall", Address: "10.0.0.1", Checks: []wire.CheckConfig{{Type: "icmp"}}, CreatedAt: now}, "test"))
	box, err := f.st.Box(ctx, "box_x")
	must(t, err)
	var rounds []wire.Round
	for i := 0; i < 3; i++ {
		rounds = append(rounds, wire.Round{At: now.Add(time.Duration(i-3) * 30 * time.Second), OK: false, Checks: []wire.CheckResult{{Type: "icmp", OK: false, Error: "timeout"}}})
	}
	hb := wire.Heartbeat{SentAt: now, Agent: wire.AgentInfo{Version: "0.1.0", OS: "linux", Arch: "amd64"}, Hosts: []wire.HostReport{{HostID: "host_x", Rounds: rounds}}}
	_, err = f.eng.Heartbeat(ctx, box, hb)
	must(t, err)
	return box
}

type overviewJSON struct {
	Attention []struct {
		Kind  string `json:"kind"`
		ID    string `json:"id"`
		Since string `json:"since"`
		Ack   *struct {
			Actor string `json:"actor"`
			Note  string `json:"note"`
		} `json:"ack"`
	} `json:"attention"`
}

func TestAcknowledgeProblem(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	seedDownHost(t, f)

	overview := func() overviewJSON {
		t.Helper()
		status, _, body := f.getJSON("/api/overview")
		if status != 200 {
			t.Fatalf("overview: %d %s", status, body)
		}
		var o overviewJSON
		must(t, json.Unmarshal([]byte(body), &o))
		return o
	}
	nav := func() int {
		t.Helper()
		_, _, body := f.getJSON("/api/me")
		var me struct{ Nav struct{ Attention int } }
		must(t, json.Unmarshal([]byte(body), &me))
		return me.Nav.Attention
	}

	o := overview()
	if len(o.Attention) != 1 || o.Attention[0].Kind != "host_down" || o.Attention[0].ID != "host_x" || o.Attention[0].Ack != nil {
		t.Fatalf("attention before ack: %+v", o.Attention)
	}
	if nav() != 1 {
		t.Fatal("nav should count the open problem")
	}

	// acknowledge with the outage start the app got from the overview
	status, body := f.postJSON("/api/ack", url.Values{"kind": {"host_down"}, "id": {"host_x"}, "since": {o.Attention[0].Since}, "note": {"Ticket 4711"}}, f.csrf)
	if status != 200 {
		t.Fatalf("ack: %d %s", status, body)
	}
	o = overview()
	if len(o.Attention) != 1 || o.Attention[0].Ack == nil || o.Attention[0].Ack.Actor != userName || o.Attention[0].Ack.Note != "Ticket 4711" {
		t.Fatalf("attention after ack: %+v", o.Attention)
	}
	if nav() != 0 {
		t.Fatal("an acknowledged problem must not count as open")
	}

	// a wrong outage start does not match: the problem stays open
	status, _ = f.postJSON("/api/ack", url.Values{"kind": {"host_down"}, "id": {"host_x"}, "since": {"2001-01-01T00:00:00Z"}}, f.csrf)
	if status != 200 {
		t.Fatalf("ack with other since: %d", status)
	}
	if o = overview(); o.Attention[0].Ack != nil {
		t.Fatal("an ack for a different outage must not apply")
	}

	// unknown kinds are refused
	if status, _ := f.postJSON("/api/ack", url.Values{"kind": {"weather"}, "id": {"x"}, "since": {"2001-01-01T00:00:00Z"}}, f.csrf); status != 400 {
		t.Fatalf("bad kind: %d", status)
	}

	// re-acknowledge, then the host recovers: the ack goes with the outage
	status, _ = f.postJSON("/api/ack", url.Values{"kind": {"host_down"}, "id": {"host_x"}, "since": {o.Attention[0].Since}}, f.csrf)
	if status != 200 {
		t.Fatal("ack again")
	}
	ctx := context.Background()
	box, _ := f.st.Box(ctx, "box_x")
	now := time.Now()
	hb := wire.Heartbeat{SentAt: now, Agent: wire.AgentInfo{Version: "0.1.0", OS: "linux", Arch: "amd64"}, Hosts: []wire.HostReport{{HostID: "host_x", Rounds: []wire.Round{
		{At: now.Add(-30 * time.Second), OK: true, Checks: []wire.CheckResult{{Type: "icmp", OK: true}}},
		{At: now, OK: true, Checks: []wire.CheckResult{{Type: "icmp", OK: true}}},
	}}}}
	_, err := f.eng.Heartbeat(ctx, box, hb)
	must(t, err)
	acks, _ := f.st.Acks(ctx)
	if len(acks) != 0 {
		t.Fatalf("ack should be gone after host.up: %+v", acks)
	}
	if o = overview(); len(o.Attention) != 0 {
		t.Fatalf("attention after recovery: %+v", o.Attention)
	}
}

func TestTasksAndUpdatesAPI(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	seedDownHost(t, f)
	ctx := context.Background()

	// queue a task for the site's box; a second one of the same kind is refused
	status, body := f.postJSON("/api/sites/site_x/tasks", url.Values{"kind": {"sweep"}}, f.csrf)
	if status != 200 || !strings.Contains(body, "eingereiht") {
		t.Fatalf("site task: %d %s", status, body)
	}
	status, body = f.postJSON("/api/boxes/box_x/tasks", url.Values{"kind": {"sweep"}}, f.csrf)
	if status != 400 || !strings.Contains(body, "wartet bereits") {
		t.Fatalf("duplicate task: %d %s", status, body)
	}
	if status, body := f.postJSON("/api/boxes/box_x/tasks", url.Values{"kind": {"shell"}}, f.csrf); status != 400 || !strings.Contains(body, "Unbekannte") {
		t.Fatalf("unknown task: %d %s", status, body)
	}
	status, _, body = f.getJSON("/api/boxes/box_x")
	if status != 200 {
		t.Fatalf("box: %d %s", status, body)
	}
	var bd struct {
		Tasks []struct {
			Kind   string
			DoneAt *string
		}
		Notes []struct{ Text string }
	}
	must(t, json.Unmarshal([]byte(body), &bd))
	if len(bd.Tasks) != 1 || bd.Tasks[0].Kind != "sweep" || bd.Tasks[0].DoneAt != nil {
		t.Fatalf("box tasks: %+v", bd.Tasks)
	}

	// updates: no release yet, then one, then a channel and a rollout
	status, _, body = f.getJSON("/api/updates")
	if status != 200 {
		t.Fatalf("updates: %d %s", status, body)
	}
	var ud struct {
		Boxes []struct {
			ID, Target string
			Behind     bool
		}
		NoTarget int
		Behind   int
	}
	must(t, json.Unmarshal([]byte(body), &ud))
	if len(ud.Boxes) != 1 || ud.NoTarget != 1 || ud.Boxes[0].Target != "" {
		t.Fatalf("updates before release: %+v", ud)
	}
	if status, body := f.postJSON("/api/updates/channel", url.Values{"channel": {"stable"}, "version": {"0.9.0"}}, f.csrf); status != 400 || !strings.Contains(body, "nicht als Release") {
		t.Fatalf("channel to unknown version: %d %s", status, body)
	}
	must(t, f.st.PutRelease(ctx, store.Release{Version: "0.9.0", OS: "linux", Arch: "amd64", URL: "https://example.test/excubra_linux_amd64", SHA256: "00", Signature: "sig", CreatedAt: time.Now()}))
	if status, body := f.postJSON("/api/updates/channel", url.Values{"channel": {"stable"}, "version": {"v0.9.0"}}, f.csrf); status != 200 {
		t.Fatalf("channel: %d %s", status, body)
	}
	status, _, body = f.getJSON("/api/updates")
	must(t, json.Unmarshal([]byte(body), &ud))
	if status != 200 || ud.Behind != 1 || !ud.Boxes[0].Behind || ud.Boxes[0].Target != "0.9.0" {
		t.Fatalf("updates after channel: %+v", ud)
	}
	status, body = f.postJSON("/api/updates/rollout", url.Values{"channel": {"stable"}}, f.csrf)
	if status != 200 || !strings.Contains(body, "an 1 Boxen") {
		t.Fatalf("rollout: %d %s", status, body)
	}
	pending, _ := f.st.PendingBoxTasks(ctx, "box_x", time.Now())
	kinds := ""
	for _, p := range pending {
		kinds += p.Kind + " "
	}
	if kinds != "sweep update " {
		t.Fatalf("pending after rollout: %q", kinds)
	}
	if status, _ := f.postJSON("/api/boxes/box_x/channel", url.Values{"channel": {"canary"}}, f.csrf); status != 200 {
		t.Fatalf("box channel: %d", status)
	}
	if b, _ := f.st.Box(ctx, "box_x"); b.Channel != "canary" {
		t.Fatalf("channel not set: %q", b.Channel)
	}
	if status, _ := f.postJSON("/api/updates/rollout", url.Values{"channel": {"canary"}}, f.csrf); status != 400 {
		t.Fatalf("rollout on a channel without a version must be refused: %d", status)
	}
}
