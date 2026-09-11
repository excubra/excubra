package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// Tasks arrive with the config, run once each, and their results ride the next
// heartbeat; a replayed config never repeats a task, and the memory survives on disk.
func TestTasksRunOnceAndReport(t *testing.T) {
	w := newWorld(t)
	a := w.agent()
	ctx := context.Background()
	a.heartbeat(ctx)
	must(t, w.eng.AssignBox(ctx, a.st.BoxID, "site_a", "test"))
	must(t, w.eng.CreateHost(ctx, store.Host{ID: "host_fw", TenantID: "ten_a", SiteID: "site_a", BoxID: a.st.BoxID, Name: "fw", Address: "192.168.1.1",
		Checks: []wire.CheckConfig{{Type: "icmp"}}, CreatedAt: time.Now()}, "test"))
	w.pinger.down["192.168.1.1"] = true

	sweep, err := w.eng.QueueTask(ctx, a.st.BoxID, wire.TaskSweep, "test")
	must(t, err)
	recheck, err := w.eng.QueueTask(ctx, a.st.BoxID, wire.TaskRecheck, "test")
	must(t, err)
	upd, err := w.eng.QueueTask(ctx, a.st.BoxID, wire.TaskUpdate, "test")
	must(t, err)
	if _, err := w.eng.QueueTask(ctx, a.st.BoxID, wire.TaskSweep, "test"); !errors.Is(err, core.ErrTaskPending) {
		t.Fatalf("a second sweep while one waits: %v", err)
	}

	// the heartbeat sees the new config version, pulls, the tasks start
	a.heartbeat(ctx)
	a.tasksWG.Wait()
	if len(a.cfg.Tasks) != 3 {
		t.Fatalf("config tasks: %+v", a.cfg.Tasks)
	}
	select {
	case <-a.updateNow:
	default:
		t.Fatal("the update task did not trigger the update check")
	}
	done, pending := a.st.LoadTasks()
	if len(done) != 3 || len(pending) != 3 {
		t.Fatalf("task memory before delivery: done=%v pending=%d", done, len(pending))
	}

	// the next heartbeat delivers the results; the server closes the tasks
	a.heartbeat(ctx)
	byID := map[string]store.BoxTask{}
	tasks, err := w.st.BoxTasks(ctx, a.st.BoxID, 10)
	must(t, err)
	for _, tk := range tasks {
		byID[tk.ID] = tk
	}
	for _, id := range []string{sweep.ID, recheck.ID, upd.ID} {
		tk := byID[id]
		if tk.DoneAt == nil || tk.OK == nil || !*tk.OK {
			t.Fatalf("task %s not closed ok: %+v", id, tk)
		}
	}
	if d := byID[recheck.ID].Detail; !strings.Contains(d, "1 hosts checked, 1 failed") {
		t.Fatalf("recheck detail: %q", d)
	}
	if _, pending := a.st.LoadTasks(); len(pending) != 0 {
		t.Fatalf("results still on disk after delivery: %d", len(pending))
	}

	// a replayed config with the same ids runs nothing again
	a.applyConfig(wire.Config{Tasks: []wire.Task{{ID: sweep.ID, Kind: wire.TaskSweep}, {ID: recheck.ID, Kind: wire.TaskRecheck}}})
	a.tasksWG.Wait()
	if rs := a.takeTaskResults(); len(rs) != 0 {
		t.Fatalf("replayed tasks ran again: %+v", rs)
	}

	// an unknown kind is refused with a result, not ignored
	a.applyConfig(wire.Config{Tasks: []wire.Task{{ID: "task_x", Kind: "shell"}}})
	a.tasksWG.Wait()
	if rs := a.takeTaskResults(); len(rs) != 1 || rs[0].OK || !strings.Contains(rs[0].Detail, "unknown task kind") {
		t.Fatalf("unknown kind: %+v", rs)
	}

	// restart: result queued, the main loop is asked to exit 75 after reporting
	restart, err := w.eng.QueueTask(ctx, a.st.BoxID, wire.TaskRestart, "test")
	must(t, err)
	a.heartbeat(ctx)
	a.tasksWG.Wait()
	select {
	case <-a.restartNow:
	default:
		t.Fatal("restart task did not ask the loop to restart")
	}
	a.heartbeat(ctx) // what the loop does before exiting
	tasks, _ = w.st.BoxTasks(ctx, a.st.BoxID, 10)
	for _, tk := range tasks {
		if tk.ID == restart.ID && (tk.DoneAt == nil || tk.Detail != "restarting") {
			t.Fatalf("restart task: %+v", tk)
		}
	}

	// a fresh agent on the same state directory remembers what ran
	b, err := newAgent(a.st, a.log, a.upd)
	must(t, err)
	if !b.doneSet[sweep.ID] || !b.doneSet[restart.ID] {
		t.Fatalf("task memory not reloaded: %v", b.doneTasks)
	}
}
