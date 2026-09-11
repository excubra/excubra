package agent

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/excubra/excubra/internal/agent/checks"
	"github.com/excubra/excubra/internal/agent/connect"
	"github.com/excubra/excubra/internal/agent/discovery"
	"github.com/excubra/excubra/internal/agent/update"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/seal"
	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

// Timing bounds. The server sets intervals; the agent clamps them so a bad
// config can neither hammer the server nor go quiet.
const (
	minHeartbeat = 30 * time.Second
	maxHeartbeat = 5 * time.Minute
	minCheck     = 10 * time.Second
	maxCheck     = 5 * time.Minute
	minConfigAge = 5 * time.Minute
	maxConfigAge = time.Hour
	renewBefore  = 30 * 24 * time.Hour
	checkHosts   = 16 // hosts checked in parallel
)

// Agent is the running box-side process.
type Agent struct {
	st     *State
	client *Client
	log    *slog.Logger
	now    func() time.Time

	checker *checks.Runner
	disc    *discovery.Discovery
	netbird *Netbird
	upd     *update.Updater
	conn    *connect.Runner
	sealKey *ecdh.PrivateKey

	cfgMu        sync.RWMutex
	cfg          wire.Config
	cfgErrors    []string
	cfgPulledAt  time.Time
	hbInterval   time.Duration
	checkEvery   time.Duration
	configMaxAge time.Duration

	roundsMu sync.Mutex
	rounds   map[string][]wire.Round
	dropped  int64

	notesMu sync.Mutex
	notes   []string

	clockOffset *int64
	updateNow   chan struct{}
	restartNow  chan struct{}

	// tasks (ADR-0014): ids already run, results waiting for a heartbeat
	tasksMu     sync.Mutex
	doneTasks   []string
	doneSet     map[string]bool
	taskResults []wire.TaskResult
	tasksWG     sync.WaitGroup // tests wait for running tasks
	baseCtx     context.Context
}

// Run is the agent main loop. It returns when ctx ends, or ErrRestart after a
// self-update (main exits 75, systemd starts the new binary).
func Run(ctx context.Context, stateDir, enrollFile string, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	st, err := OpenState(stateDir)
	if err != nil {
		return err
	}
	log.Info("excubra agent starting", "version", version.Version, "state", st.Dir)
	if err := waitForEnrollment(ctx, st, enrollFile, log); err != nil {
		return err
	}
	upd, err := update.New(stateDir, log)
	if err != nil {
		return err
	}
	if err := upd.RollbackIfStale(); err != nil {
		return err // ErrRestart: the previous build never confirmed, we put the old one back
	}
	a, err := newAgent(st, log, upd)
	if err != nil {
		return err
	}
	if rb, ok := upd.RolledBack(); ok {
		a.note(fmt.Sprintf("update to %s rolled back to %s", rb.To, rb.From))
	}
	return a.run(ctx)
}

// waitForEnrollment enrolls with the image's key file when there is one, or waits
// quietly for it to appear. Restart loops with error spam help nobody.
func waitForEnrollment(ctx context.Context, st *State, enrollFile string, log *slog.Logger) error {
	for !st.Enrolled() {
		if key, from := ReadEnrollmentKey(EnrollKeyPaths(st.Dir, enrollFile)...); key != "" {
			if err := Enroll(ctx, st, key, "", log); err != nil {
				var se *ServerError
				if errors.As(err, &se) && !se.Retryable() {
					log.Error("enrollment refused, the key is not usable", "err", err)
					DeleteEnrollmentKeyFile(from)
				} else {
					log.Warn("enrollment failed, retrying", "err", err)
				}
			} else {
				DeleteEnrollmentKeyFile(from)
				continue
			}
		} else {
			log.Warn("not enrolled: waiting for an enrollment key (excubra agent enroll --key …)")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}
	return nil
}

func newAgent(st *State, log *slog.Logger, upd *update.Updater) (*Agent, error) {
	client, err := NewClient(st.Server, st.CAFingerprint, st)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		st: st, client: client, log: log, now: time.Now,
		checker:    checks.NewRunner(checks.NewPinger()),
		disc:       discovery.New(log),
		netbird:    NewNetbird(st.Dir),
		upd:        upd,
		rounds:     map[string][]wire.Round{},
		updateNow:  make(chan struct{}, 1),
		restartNow: make(chan struct{}, 1),
		doneSet:    map[string]bool{},
		baseCtx:    context.Background(),
	}
	key, err := st.SealKey()
	if err != nil {
		return nil, err
	}
	a.sealKey = key
	a.conn = connect.New(log, func(sealed string) ([]byte, error) { return seal.Open(key, sealed) })
	a.hbInterval, a.checkEvery, a.configMaxAge = 60*time.Second, 30*time.Second, 15*time.Minute
	a.doneTasks, a.taskResults = st.LoadTasks()
	for _, id := range a.doneTasks {
		a.doneSet[id] = true
	}
	if cfg, ok := st.LoadConfig(); ok {
		a.applyConfig(cfg)
		a.cfgPulledAt = time.Time{} // from disk: pull again soon
	}
	return a, nil
}

func (a *Agent) run(ctx context.Context) error {
	a.baseCtx = ctx
	go a.disc.Run(ctx)
	go a.conn.Run(ctx)
	go a.checkLoop(ctx)

	hb := time.NewTimer(5 * time.Second)
	defer hb.Stop()
	renew := time.NewTicker(24 * time.Hour)
	defer renew.Stop()
	updateTick := time.NewTimer(10*time.Minute + time.Duration(rand.IntN(300))*time.Second) //nolint:gosec // jitter, not security
	defer updateTick.Stop()
	confirmDeadline := time.NewTimer(update.ConfirmWithin)
	defer confirmDeadline.Stop()
	a.renewIfDue(ctx)

	for {
		select {
		case <-ctx.Done():
			a.log.Info("agent stopping")
			return nil
		case <-hb.C:
			a.heartbeat(ctx)
			hb.Reset(a.interval())
		case <-renew.C:
			a.renewIfDue(ctx)
		case <-updateTick.C:
			if err := a.checkUpdate(ctx); err != nil {
				return err
			}
			updateTick.Reset(24*time.Hour + time.Duration(rand.IntN(3600))*time.Second) //nolint:gosec
		case <-a.updateNow:
			if err := a.checkUpdate(ctx); err != nil {
				return err
			}
		case <-a.restartNow:
			// the "restart" task: report it first, then let the service manager start us again
			a.heartbeat(ctx)
			a.log.Info("restarting as requested by a task")
			return update.ErrRestart
		case <-confirmDeadline.C:
			// a freshly installed build that never managed a heartbeat is rolled back
			if err := a.upd.RollbackIfStale(); err != nil {
				return err
			}
		}
	}
}

func (a *Agent) interval() time.Duration {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.hbInterval
}

// ---- checks -------------------------------------------------------------------------

func (a *Agent) checkLoop(ctx context.Context) {
	t := time.NewTimer(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.cfgMu.RLock()
		hosts := append([]wire.HostConfig(nil), a.cfg.Hosts...)
		every := a.checkEvery
		a.cfgMu.RUnlock()
		a.runRounds(ctx, hosts)
		t.Reset(every)
	}
}

// runRounds checks every host once, in parallel, and reports how many failed.
func (a *Agent) runRounds(ctx context.Context, hosts []wire.HostConfig) (checked, failed int) {
	sem := make(chan struct{}, checkHosts)
	var wg sync.WaitGroup
	var nFailed atomic.Int64
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h wire.HostConfig) {
			defer wg.Done()
			defer func() { <-sem }()
			r := a.checker.Round(ctx, h)
			if !r.OK {
				nFailed.Add(1)
			}
			a.addRound(h.HostID, r)
		}(h)
	}
	wg.Wait()
	return len(hosts), int(nFailed.Load())
}

func (a *Agent) addRound(hostID string, r wire.Round) {
	a.roundsMu.Lock()
	defer a.roundsMu.Unlock()
	rs := append(a.rounds[hostID], r)
	if len(rs) > wire.MaxRoundsPerHost {
		a.dropped += int64(len(rs) - wire.MaxRoundsPerHost)
		rs = rs[len(rs)-wire.MaxRoundsPerHost:]
	}
	a.rounds[hostID] = rs
}

// takeRounds snapshots the accumulated rounds; the caller gives them back with
// putRounds if the heartbeat fails.
func (a *Agent) takeRounds() ([]wire.HostReport, int64) {
	a.roundsMu.Lock()
	defer a.roundsMu.Unlock()
	var out []wire.HostReport
	for id, rs := range a.rounds {
		out = append(out, wire.HostReport{HostID: id, Rounds: rs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	a.rounds = map[string][]wire.Round{}
	d := a.dropped
	return out, d
}

func (a *Agent) putRounds(reports []wire.HostReport) {
	a.roundsMu.Lock()
	defer a.roundsMu.Unlock()
	for _, rep := range reports {
		rs := append(rep.Rounds, a.rounds[rep.HostID]...)
		if len(rs) > wire.MaxRoundsPerHost {
			a.dropped += int64(len(rs) - wire.MaxRoundsPerHost)
			rs = rs[len(rs)-wire.MaxRoundsPerHost:]
		}
		a.rounds[rep.HostID] = rs
	}
}

func (a *Agent) note(s string) {
	a.notesMu.Lock()
	a.notes = append(a.notes, s)
	a.notesMu.Unlock()
	a.log.Warn(s)
}

func (a *Agent) takeNotes() []string {
	a.notesMu.Lock()
	defer a.notesMu.Unlock()
	n := a.notes
	a.notes = nil
	return n
}

// ---- heartbeat ----------------------------------------------------------------------

func (a *Agent) heartbeat(ctx context.Context) {
	reports, dropped := a.takeRounds()
	sightings := a.disc.Sightings(ctx)
	notes := a.takeNotes()
	results := a.takeTaskResults()
	var conns []wire.ConnectorReport
	if a.conn != nil {
		conns = a.conn.Reports()
	}
	a.cfgMu.RLock()
	cfgVersion, cfgErrors := a.cfg.Version, append([]string(nil), a.cfgErrors...)
	a.cfgMu.RUnlock()
	queued := 0
	for _, r := range reports {
		queued += len(r.Rounds)
	}
	hb := wire.Heartbeat{
		SentAt:        a.now().UTC(),
		Agent:         wire.AgentInfo{Version: version.Version, UptimeS: uptimeSeconds(), BootID: bootID(), OS: runtime.GOOS, Arch: runtime.GOARCH, SealKey: a.sealPublic()},
		Box:           boxInfo(a.st.Dir),
		Netbird:       a.netbird.Status(ctx),
		ConfigVersion: cfgVersion,
		ConfigErrors:  cfgErrors,
		Notes:         notes,
		Hosts:         reports,
		Discovery:     wire.DiscoveryReport{Seen: sightings},
		Buffer:        wire.BufferInfo{Queued: queued, Dropped: dropped},
		TaskResults:   results,
		Connectors:    conns,
	}
	hb.Box.ClockOffsetMS = a.clockOffset

	cctx, cancel := context.WithTimeout(ctx, requestTimeout)
	resp, err := a.client.Heartbeat(cctx, hb)
	cancel()
	if err != nil {
		a.putRounds(reports)
		a.disc.Table.Nack()
		if a.conn != nil {
			a.conn.Nack()
		}
		a.putTaskResults(results)
		if len(notes) > 0 {
			a.notesMu.Lock()
			a.notes = append(notes, a.notes...)
			a.notesMu.Unlock()
		}
		var se *ServerError
		switch {
		case errors.As(err, &se) && se.Code == wire.ErrUpgradeRequired:
			a.log.Warn("server requires a newer agent, checking for an update")
			select {
			case a.updateNow <- struct{}{}:
			default:
			}
		case errors.As(err, &se) && se.Code == wire.ErrRevoked:
			a.log.Error("this box is revoked; it needs a new enrollment", "err", err)
		default:
			a.log.Warn("heartbeat failed", "err", err)
		}
		return
	}
	a.disc.Table.Ack()
	if a.conn != nil {
		a.conn.Ack()
	}
	a.upd.Confirm()
	if len(results) > 0 {
		a.saveTasks()
	}
	off := hb.SentAt.Sub(resp.ServerTime).Milliseconds()
	a.clockOffset = &off
	a.log.Debug("heartbeat ok", "hosts", len(reports), "sightings", len(sightings), "assigned", resp.Assigned)

	a.cfgMu.RLock()
	stale := resp.ConfigVersion != a.cfg.Version || a.now().Sub(a.cfgPulledAt) > a.configMaxAge
	a.cfgMu.RUnlock()
	if stale {
		a.pullConfig(ctx)
	}
}

// ---- config ---------------------------------------------------------------------------

func (a *Agent) pullConfig(ctx context.Context) {
	a.cfgMu.RLock()
	etag := a.cfg.Version
	a.cfgMu.RUnlock()
	cctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	cfg, notModified, err := a.client.Config(cctx, etag)
	if err != nil {
		a.log.Warn("config pull failed", "err", err)
		return
	}
	a.cfgMu.Lock()
	a.cfgPulledAt = a.now()
	a.cfgMu.Unlock()
	if notModified {
		return
	}
	a.applyConfig(cfg)
	if err := a.st.SaveConfig(cfg); err != nil {
		a.log.Warn("saving config", "err", err)
	}
	a.log.Info("config applied", "version", cfg.Version, "hosts", len(cfg.Hosts), "discovery", cfg.Discovery.Mode, "assigned", cfg.Assigned)
	if cfg.NetbirdPending {
		a.claimNetbird(ctx)
	}
}

func (a *Agent) applyConfig(cfg wire.Config) {
	errs := checks.Validate(cfg.Hosts)
	dcfg, derrs := discovery.ParseConfig(cfg.Discovery)
	errs = append(errs, derrs...)
	a.disc.Apply(dcfg)

	a.cfgMu.Lock()
	a.cfg = cfg
	a.cfgErrors = errs
	a.hbInterval = clamp(time.Duration(cfg.Intervals.HeartbeatS)*time.Second, minHeartbeat, maxHeartbeat, 60*time.Second)
	a.checkEvery = clamp(time.Duration(cfg.Intervals.CheckS)*time.Second, minCheck, maxCheck, 30*time.Second)
	a.configMaxAge = clamp(time.Duration(cfg.Intervals.ConfigMaxAgeS)*time.Second, minConfigAge, maxConfigAge, 15*time.Minute)
	a.cfgMu.Unlock()

	// hosts that vanished from the config take their pending rounds with them
	a.roundsMu.Lock()
	keep := map[string]bool{}
	for _, h := range cfg.Hosts {
		keep[h.HostID] = true
	}
	for id := range a.rounds {
		if !keep[id] {
			delete(a.rounds, id)
		}
	}
	a.roundsMu.Unlock()

	a.startTasks(cfg.Tasks)
	if a.conn != nil { // unit tests build agents without a runner
		a.conn.Apply(cfg.Connectors)
	}
}

// ---- tasks (ADR-0014) ------------------------------------------------------------------------

// startTasks runs every task of the config that has not run yet, each once, in the
// background. The id is remembered before the task starts so a config pulled twice
// or a restart mid-task never repeats it.
func (a *Agent) startTasks(tasks []wire.Task) {
	if len(tasks) > wire.MaxTasks {
		tasks = tasks[:wire.MaxTasks]
	}
	a.tasksMu.Lock()
	var fresh []wire.Task
	for _, t := range tasks {
		if t.ID == "" || a.doneSet[t.ID] {
			continue
		}
		a.doneSet[t.ID] = true
		a.doneTasks = append(a.doneTasks, t.ID)
		fresh = append(fresh, t)
	}
	if len(fresh) > 0 {
		a.saveTasksLocked()
	}
	a.tasksMu.Unlock()
	for _, t := range fresh {
		a.tasksWG.Add(1)
		go func(t wire.Task) {
			defer a.tasksWG.Done()
			a.runTask(a.baseCtx, t)
		}(t)
	}
}

// runTask executes one task and queues its result for the next heartbeat.
func (a *Agent) runTask(ctx context.Context, t wire.Task) {
	res := wire.TaskResult{ID: t.ID, Kind: t.Kind, OK: true}
	a.log.Info("task", "kind", t.Kind, "id", t.ID)
	switch t.Kind {
	case wire.TaskSweep:
		n := a.disc.SweepNow(ctx)
		res.Detail = fmt.Sprintf("sweep done, %d devices in the table", n)
	case wire.TaskRecheck:
		a.cfgMu.RLock()
		hosts := append([]wire.HostConfig(nil), a.cfg.Hosts...)
		a.cfgMu.RUnlock()
		checked, failed := a.runRounds(ctx, hosts)
		res.Detail = fmt.Sprintf("%d hosts checked, %d failed", checked, failed)
	case wire.TaskUpdate:
		select {
		case a.updateNow <- struct{}{}:
		default:
		}
		res.Detail = "update check triggered"
	case wire.TaskRestart:
		res.Detail = "restarting"
		res.FinishedAt = a.now().UTC()
		a.addTaskResult(res)
		select {
		case a.restartNow <- struct{}{}:
		default:
		}
		return
	default:
		res.OK = false
		res.Detail = "unknown task kind " + t.Kind
	}
	res.FinishedAt = a.now().UTC()
	a.addTaskResult(res)
}

func (a *Agent) addTaskResult(r wire.TaskResult) {
	a.tasksMu.Lock()
	a.taskResults = append(a.taskResults, r)
	a.saveTasksLocked()
	a.tasksMu.Unlock()
}

func (a *Agent) takeTaskResults() []wire.TaskResult {
	a.tasksMu.Lock()
	defer a.tasksMu.Unlock()
	r := a.taskResults
	a.taskResults = nil
	return r
}

func (a *Agent) putTaskResults(rs []wire.TaskResult) {
	if len(rs) == 0 {
		return
	}
	a.tasksMu.Lock()
	a.taskResults = append(rs, a.taskResults...)
	a.tasksMu.Unlock()
}

func (a *Agent) saveTasks() {
	a.tasksMu.Lock()
	a.saveTasksLocked()
	a.tasksMu.Unlock()
}

func (a *Agent) saveTasksLocked() {
	if err := a.st.SaveTasks(a.doneTasks, a.taskResults); err != nil {
		a.log.Warn("saving task memory", "err", err)
	}
	if len(a.doneTasks) > maxDoneTasks {
		a.doneTasks = a.doneTasks[len(a.doneTasks)-maxDoneTasks:]
		a.doneSet = map[string]bool{}
		for _, id := range a.doneTasks {
			a.doneSet[id] = true
		}
	}
}

func clamp(d, lo, hi, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

func (a *Agent) claimNetbird(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, requestTimeout)
	claim, ok, err := a.client.ClaimNetbird(cctx)
	cancel()
	if err != nil {
		a.log.Warn("netbird claim failed", "err", err)
		return
	}
	if !ok {
		return
	}
	if err := a.netbird.Up(ctx, claim.ManagementURL, claim.SetupKey); err != nil {
		a.note("netbird up failed: " + err.Error())
		return
	}
	a.log.Info("netbird connected", "management", claim.ManagementURL)
}

// ---- renewal and update ------------------------------------------------------------------

func (a *Agent) renewIfDue(ctx context.Context) {
	notAfter, err := a.st.CertNotAfter()
	if err != nil || a.now().Add(renewBefore).Before(notAfter) {
		return
	}
	priv, err := a.st.Key()
	if err != nil {
		a.log.Error("renewal: key", "err", err)
		return
	}
	csr, err := pki.CSRPEM(priv, hardwareID())
	if err != nil {
		a.log.Error("renewal: csr", "err", err)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := a.client.Renew(cctx, string(csr))
	if err != nil {
		a.log.Warn("renewal failed, will retry tomorrow", "err", err)
		return
	}
	if err := a.st.SaveCertificate(resp.Certificate); err != nil {
		a.log.Error("renewal: saving certificate", "err", err)
		return
	}
	client, err := NewClient(a.st.Server, a.st.CAFingerprint, a.st)
	if err != nil {
		a.log.Error("renewal: client", "err", err)
		return
	}
	a.client = client
	a.log.Info("certificate renewed", "not_after", resp.NotAfter)
}

func (a *Agent) checkUpdate(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, requestTimeout)
	info, ok, err := a.client.UpdateInfo(cctx, runtime.GOOS, runtime.GOARCH)
	cancel()
	if err != nil {
		a.log.Warn("update check failed", "err", err)
		return nil
	}
	if !ok {
		return nil
	}
	err = a.upd.Apply(ctx, info)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, update.ErrRestart):
		return err
	default:
		a.note("update to " + info.Version + " not installed: " + err.Error())
		return nil
	}
}

// sealPublic is the seal key the console seals credentials to ("" without a key).
func (a *Agent) sealPublic() string {
	if a.sealKey == nil {
		return ""
	}
	return seal.Public(a.sealKey)
}
