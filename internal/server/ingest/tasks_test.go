package ingest_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/wire"
)

// A task travels with the config, comes back as a result in a heartbeat, is closed
// exactly once, and expires when the box never picks it up (ADR-0014).
func TestTasksTravelWithConfigAndCloseOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	boxID, client, status := f.enroll(f.key.String())
	if status != 200 {
		t.Fatalf("enroll: %d", status)
	}
	must(t, f.eng.AssignBox(ctx, boxID, "site_a", "test"))

	hb := func(results []wire.TaskResult, notes []string) wire.HeartbeatResponse {
		t.Helper()
		status, body := f.do(client, "POST", "/v1/heartbeat", wire.Heartbeat{SentAt: f.now, Agent: wire.AgentInfo{Version: "0.0.0", OS: "linux", Arch: "arm64"}, TaskResults: results, Notes: notes}, nil)
		if status != 200 {
			t.Fatalf("heartbeat: %d %s", status, body)
		}
		var resp wire.HeartbeatResponse
		must(t, json.Unmarshal(body, &resp))
		return resp
	}
	before := hb(nil, nil)

	// queue: valid kind, one per kind, unknown kinds refused
	task, err := f.eng.QueueTask(ctx, boxID, wire.TaskSweep, "jeremia")
	must(t, err)
	if _, err := f.eng.QueueTask(ctx, boxID, wire.TaskSweep, "jeremia"); !errors.Is(err, core.ErrTaskPending) {
		t.Fatalf("second sweep while one is pending: %v", err)
	}
	if _, err := f.eng.QueueTask(ctx, boxID, "rm -rf", "jeremia"); !errors.Is(err, core.ErrBadTask) {
		t.Fatalf("unknown kind: %v", err)
	}

	// the config version changes, the config carries the task
	after := hb(nil, nil)
	if after.ConfigVersion == before.ConfigVersion {
		t.Fatal("queueing a task must change the config version, or the box never pulls")
	}
	status, body := f.do(client, "GET", "/v1/config", nil, nil)
	if status != 200 {
		t.Fatalf("config: %d %s", status, body)
	}
	var cfg wire.Config
	must(t, json.Unmarshal(body, &cfg))
	if len(cfg.Tasks) != 1 || cfg.Tasks[0].ID != task.ID || cfg.Tasks[0].Kind != wire.TaskSweep {
		t.Fatalf("config tasks: %+v", cfg.Tasks)
	}

	// the result closes the task; a repeated delivery changes nothing
	res := []wire.TaskResult{{ID: task.ID, Kind: wire.TaskSweep, OK: true, Detail: "sweep done, 12 devices in the table", FinishedAt: f.now}}
	hb(res, []string{"update to 9.9.9 not installed: sig: no release key embedded"})
	f.now = f.now.Add(time.Minute)
	hb(res, nil)
	tasks, err := f.st.BoxTasks(ctx, boxID, 10)
	must(t, err)
	if len(tasks) != 1 || tasks[0].DoneAt == nil || tasks[0].OK == nil || !*tasks[0].OK || tasks[0].Detail != "sweep done, 12 devices in the table" {
		t.Fatalf("task after result: %+v", tasks)
	}
	if !tasks[0].DoneAt.Equal(f.now.Add(-time.Minute)) {
		t.Fatalf("done_at must be the first delivery, got %v", tasks[0].DoneAt)
	}
	status, body = f.do(client, "GET", "/v1/config", nil, nil)
	var cfg2 wire.Config // fresh: Unmarshal leaves absent fields alone
	must(t, json.Unmarshal(body, &cfg2))
	if status != 200 || len(cfg2.Tasks) != 0 {
		t.Fatalf("done task still in config: %+v", cfg2.Tasks)
	}

	// the note the agent sent is kept for the operator
	notes, err := f.st.BoxNotes(ctx, boxID, 10)
	must(t, err)
	if len(notes) != 1 || notes[0].Text != "update to 9.9.9 not installed: sig: no release key embedded" {
		t.Fatalf("notes: %+v", notes)
	}

	// a task nobody picks up expires as failed
	slow, err := f.eng.QueueTask(ctx, boxID, wire.TaskRecheck, "jeremia")
	must(t, err)
	f.now = f.now.Add(core.TaskTTL + time.Minute)
	must(t, f.eng.Tick(ctx))
	tasks, _ = f.st.BoxTasks(ctx, boxID, 10)
	var expired bool
	for _, tk := range tasks {
		if tk.ID == slow.ID {
			expired = tk.DoneAt != nil && tk.OK != nil && !*tk.OK
		}
	}
	if !expired {
		t.Fatalf("task not expired: %+v", tasks)
	}
	// and a late result for it is ignored
	hb([]wire.TaskResult{{ID: slow.ID, Kind: wire.TaskRecheck, OK: true, FinishedAt: f.now}}, nil)
	tasks, _ = f.st.BoxTasks(ctx, boxID, 10)
	for _, tk := range tasks {
		if tk.ID == slow.ID && *tk.OK {
			t.Fatal("late result revived an expired task")
		}
	}
}
