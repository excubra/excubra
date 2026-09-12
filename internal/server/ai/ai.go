// Package ai is the third layer of prevention (salt: Vollausbau 3.8, decision
// E21): a model reads a site's situation — inventory, services, findings,
// events, connector facts — and writes an assessment: what matters, why, what to
// do, plus findings the rules could not see. It reads and proposes; it never
// acts (E15, E16). The provider is exchangeable; per tenant a switch says what may
// leave the server; every call is audited with what was sent.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/store"
)

// Settings keys.
const (
	SettingProvider = "ai.provider" // anthropic | openai | off
	SettingURL      = "ai.url"      // base URL; empty means the provider's own
	SettingModel    = "ai.model"
	SettingKey      = "ai.api_key" //nolint:gosec // a settings key, not a credential
)

// Defaults.
const (
	DefaultAnthropicURL   = "https://api.anthropic.com"
	DefaultAnthropicModel = "claude-fable-5-1"
	DefaultOpenAIURL      = "http://127.0.0.1:11434" // a local Ollama
	maxTokens             = 4000
	keepBriefs            = 30
	nightlyHour           = 5
)

// Errors a caller can explain to a person.
var (
	ErrNotConfigured = errors.New("ai: no provider configured")
	ErrScopeOff      = errors.New("ai: the tenant's switch is off, nothing leaves the server")
	ErrBusy          = errors.New("ai: an assessment of this site is running")
)

// Service runs assessments.
type Service struct {
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time
	Loc   *time.Location
	HTTP  *http.Client
	// NewProvider builds the backend from settings; tests replace it.
	NewProvider func(provider, url, model, key string) Provider

	mu      sync.Mutex
	busy    map[string]bool
	lastDay string
}

// New returns a service.
func New(st *store.Store, log *slog.Logger, loc *time.Location) *Service {
	if log == nil {
		log = slog.Default()
	}
	if loc == nil {
		loc = time.Local
	}
	s := &Service{Store: st, Log: log, Now: time.Now, Loc: loc, HTTP: &http.Client{Timeout: 3 * time.Minute}, busy: map[string]bool{}}
	s.NewProvider = func(provider, url, model, key string) Provider {
		switch provider {
		case "anthropic":
			return &Anthropic{URL: firstNonEmpty(url, DefaultAnthropicURL), Key: key, Mdl: firstNonEmpty(model, DefaultAnthropicModel), HTTP: s.HTTP}
		case "openai":
			return &OpenAI{URL: firstNonEmpty(url, DefaultOpenAIURL), Key: key, Mdl: model, HTTP: s.HTTP}
		}
		return nil
	}
	return s
}

// Settings is the configuration as the console shows it — never the key.
type Settings struct {
	Provider string `json:"provider"`
	URL      string `json:"url"`
	Model    string `json:"model"`
	HasKey   bool   `json:"hasKey"`
}

func (s *Service) setting(ctx context.Context, key, def string) string {
	v, err := s.Store.Setting(ctx, key)
	if err != nil || v == "" {
		return def
	}
	return v
}

// Settings returns the configuration.
func (s *Service) Settings(ctx context.Context) Settings {
	return Settings{Provider: s.setting(ctx, SettingProvider, "off"), URL: s.setting(ctx, SettingURL, ""), Model: s.setting(ctx, SettingModel, ""), HasKey: s.setting(ctx, SettingKey, "") != ""}
}

// SaveSettings stores provider, URL, model and, when given, a new key.
func (s *Service) SaveSettings(ctx context.Context, provider, url, model, key string) error {
	provider = strings.TrimSpace(provider)
	if provider != "anthropic" && provider != "openai" && provider != "off" {
		return errors.New("ai: provider must be anthropic, openai or off")
	}
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if url != "" && !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://127.0.0.1") && !strings.HasPrefix(url, "http://localhost") && !strings.HasPrefix(url, "http://10.") && !strings.HasPrefix(url, "http://192.168.") {
		return errors.New("ai: the URL must be https://, or http:// on this host or in the LAN (a local Ollama)")
	}
	for k, v := range map[string]string{SettingProvider: provider, SettingURL: url, SettingModel: strings.TrimSpace(model)} {
		if err := s.Store.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	if key = strings.TrimSpace(key); key != "" {
		if err := s.Store.SetSetting(ctx, SettingKey, key); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) provider(ctx context.Context) (Provider, error) {
	st := s.Settings(ctx)
	if st.Provider == "off" || st.Provider == "" {
		return nil, ErrNotConfigured
	}
	p := s.NewProvider(st.Provider, st.URL, st.Model, s.setting(ctx, SettingKey, ""))
	if p == nil {
		return nil, ErrNotConfigured
	}
	if st.Provider == "anthropic" && !st.HasKey {
		return nil, ErrNotConfigured
	}
	return p, nil
}

// Busy reports whether an assessment of the site is running.
func (s *Service) Busy(siteID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.busy[siteID]
}

// Test asks the model for one word and returns what came back.
func (s *Service) Test(ctx context.Context) (string, error) {
	p, err := s.provider(ctx)
	if err != nil {
		return "", err
	}
	res, err := p.Complete(ctx, Request{System: "Antworte mit genau einem Wort.", User: "Sag OK.", MaxTokens: 10})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Text), nil
}

// Result is the model's structured answer.
type Result struct {
	Risk       string     `json:"risk"`
	Summary    string     `json:"summary"`
	Priorities []Priority `json:"priorities"`
	Findings   []Finding  `json:"findings"`
}

type Priority struct {
	Title    string `json:"title"`
	Why      string `json:"why"`
	Action   string `json:"action"`
	DeviceID string `json:"device_id,omitempty"`
	Severity string `json:"severity"`
}

type Finding struct {
	DeviceID string `json:"device_id"`
	Slug     string `json:"slug"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

const systemPrompt = `Du bist die Präventions-Auswertung von EX0, einem Monitoring für kleine Firmennetze, betrieben von einem IT-Dienstleister für seine Kunden.
Du bekommst das Lagebild eines Standorts als JSON: Box, Geräte mit ihren Diensten (aus dem Scan), die Außenansicht der öffentlichen Adresse, Findings der deterministischen Regeln, Ereignisse der letzten 24 Stunden, Facts aus Geräte-Konnektoren.
Aufgabe: Als erfahrener IT-Sicherheitstechniker einordnen, was für diesen Kunden wirklich zählt. Denke an: offene Türen von außen, Kombinationen (z. B. alter Server plus RDP plus kein Backup), Geräte ohne Support, Auffälligkeiten im Inventar, was ein automatisierter Angreifer zuerst ausnutzen würde.
Antworte ausschließlich mit einem JSON-Objekt nach diesem Schema, ohne Markdown, ohne Text davor oder danach:
{"risk":"hoch|mittel|niedrig","summary":"2-4 Sätze auf Deutsch, konkret, ohne Floskeln, für den Techniker","priorities":[{"title":"...","why":"...","action":"was konkret zu tun ist","device_id":"id aus dem Lagebild oder leer","severity":"high|medium|low"}],"findings":[{"device_id":"id aus dem Lagebild","slug":"kurz_snake_case","severity":"high|medium|low","title":"...","detail":"was, warum, was tun"}]}
Regeln: priorities höchstens 6, nach Dringlichkeit geordnet, jede mit einer ausführbaren Handlung. findings nur für Dinge, die die Regeln NICHT bereits als Finding führen (Korrelationen, gefährliche Kombinationen, Auffälligkeiten), höchstens 8, jedes an ein Gerät aus dem Lagebild gebunden, keine Wiederholung der Regel-Findings. Du führst nichts aus und schlägst keine Befehle vor, du ordnest ein und empfiehlst. Wenn nichts Ernstes vorliegt, sag das in einem Satz und lass die Listen kurz.`

// Assess writes an assessment for a site now.
func (s *Service) Assess(ctx context.Context, siteID, actor string) (store.AIBrief, error) {
	s.mu.Lock()
	if s.busy[siteID] {
		s.mu.Unlock()
		return store.AIBrief{}, ErrBusy
	}
	s.busy[siteID] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.busy, siteID)
		s.mu.Unlock()
	}()
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		return store.AIBrief{}, err
	}
	tenant, err := s.Store.Tenant(ctx, site.TenantID)
	if err != nil {
		return store.AIBrief{}, err
	}
	if tenant.AIScope != store.AIScopeFacts {
		return store.AIBrief{}, ErrScopeOff
	}
	p, err := s.provider(ctx)
	if err != nil {
		return store.AIBrief{}, err
	}
	pk, devices := s.packet(ctx, tenant, site)
	user, err := json.Marshal(pk)
	if err != nil {
		return store.AIBrief{}, err
	}
	started := s.Now()
	res, err := p.Complete(ctx, Request{System: systemPrompt, User: string(user), MaxTokens: maxTokens})
	took := s.Now().Sub(started)
	_ = s.Store.Audit(ctx, s.Now(), actor, "ai.assess", siteID, fmt.Sprintf("provider=%s model=%s sent=%dB got=%dB tokens=%d/%d %s err=%v", p.Name(), p.Model(), len(user), len(res.Text), res.InputTokens, res.OutputTokens, took.Round(time.Millisecond), err))
	if err != nil {
		return store.AIBrief{}, fmt.Errorf("ai: %w", err)
	}
	r, err := parseResult(res.Text)
	if err != nil {
		return store.AIBrief{}, fmt.Errorf("ai: the model did not answer in the agreed shape: %w", err)
	}
	r = sanitize(r, devices)
	body, _ := json.Marshal(r)
	brief := store.AIBrief{ID: id.New("brief"), SiteID: siteID, TenantID: tenant.ID, At: s.Now(), Provider: p.Name(), Model: p.Model(), Risk: r.Risk, Summary: r.Summary, Body: body,
		PromptBytes: len(user), ResponseBytes: len(res.Text), DurationMS: int(took.Milliseconds()), RequestedBy: actor}
	if err := s.Store.SetAIBrief(ctx, brief); err != nil {
		return brief, err
	}
	_ = s.Store.PruneAIBriefs(ctx, siteID, keepBriefs)
	s.syncFindings(ctx, tenant, site, r, devices, brief.Model)
	s.Log.Info("ai: assessed", "site", siteID, "risk", r.Risk, "priorities", len(r.Priorities), "findings", len(r.Findings), "took", took.Round(time.Millisecond))
	return brief, nil
}

// Packet builds the situation of a site as the model would see it — for a person
// or a session model that does the reading itself (the pilot before an API key).
func (s *Service) Packet(ctx context.Context, siteID string) (Packet, error) {
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		return Packet{}, err
	}
	tenant, err := s.Store.Tenant(ctx, site.TenantID)
	if err != nil {
		return Packet{}, err
	}
	pk, _ := s.packet(ctx, tenant, site)
	return pk, nil
}

// Import stores an assessment somebody else wrote from the packet — a session
// model, a person — the same way Assess stores the model's: sanitised, as a brief,
// its device-bound findings under the source "ki", audited.
func (s *Service) Import(ctx context.Context, siteID, actor, provider, model string, r Result, promptBytes int) (store.AIBrief, error) {
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		return store.AIBrief{}, err
	}
	tenant, err := s.Store.Tenant(ctx, site.TenantID)
	if err != nil {
		return store.AIBrief{}, err
	}
	_, devices := s.packet(ctx, tenant, site)
	r = sanitize(r, devices)
	body, _ := json.Marshal(r)
	brief := store.AIBrief{ID: id.New("brief"), SiteID: siteID, TenantID: tenant.ID, At: s.Now(), Provider: firstNonEmpty(provider, "session"), Model: firstNonEmpty(model, "session"), Risk: r.Risk, Summary: r.Summary, Body: body,
		PromptBytes: promptBytes, ResponseBytes: len(body), RequestedBy: actor}
	if err := s.Store.SetAIBrief(ctx, brief); err != nil {
		return brief, err
	}
	_ = s.Store.PruneAIBriefs(ctx, siteID, keepBriefs)
	s.syncFindings(ctx, tenant, site, r, devices, brief.Model)
	_ = s.Store.Audit(ctx, s.Now(), actor, "ai.import", siteID, fmt.Sprintf("provider=%s model=%s risk=%s priorities=%d findings=%d", brief.Provider, brief.Model, r.Risk, len(r.Priorities), len(r.Findings)))
	return brief, nil
}

// ParseResult reads a model's JSON answer, tolerating fences and text around it.
func ParseResult(text string) (Result, error) { return parseResult(text) }

// syncFindings turns the model's device-bound findings into findings of source
// "ki": one sync per device of the packet, so old ones resolve.
func (s *Service) syncFindings(ctx context.Context, tenant store.Tenant, site store.Site, r Result, devices map[string]bool, model string) {
	byDevice := map[string][]store.Finding{}
	for _, f := range r.Findings {
		ev, _ := json.Marshal(map[string]any{"from": "ki", "model": model})
		byDevice[f.DeviceID] = append(byDevice[f.DeviceID], store.Finding{ID: id.New("fnd"), TenantID: tenant.ID, SiteID: site.ID, DeviceID: f.DeviceID, ConnectorID: "ki",
			Rule: "ki." + f.Slug, Key: "", Severity: f.Severity, Title: f.Title, Detail: f.Detail, Evidence: ev})
	}
	for devID := range devices {
		resolved, err := s.Store.SyncDeviceFindings(ctx, devID, "ki", byDevice[devID], s.Now())
		if err != nil {
			s.Log.Error("ai: findings", "device", devID, "err", err)
			continue
		}
		for _, fid := range resolved {
			_ = s.Store.DeleteAck(ctx, "finding", fid)
		}
	}
}

var (
	fenceRe = regexp.MustCompile("(?s)```[a-zA-Z]*\\s*(.*?)```")
	slugRe  = regexp.MustCompile(`[^a-z0-9_]+`)
)

// parseResult reads the model's JSON, tolerating fences and text around it.
func parseResult(text string) (Result, error) {
	t := strings.TrimSpace(text)
	if m := fenceRe.FindStringSubmatch(t); m != nil {
		t = m[1]
	}
	if i := strings.Index(t, "{"); i >= 0 {
		if j := strings.LastIndex(t, "}"); j > i {
			t = t[i : j+1]
		}
	}
	var r Result
	if err := json.Unmarshal([]byte(t), &r); err != nil {
		return Result{}, err
	}
	return r, nil
}

// sanitize keeps the answer within the schema: known risks and severities,
// findings only for devices of the packet, bounded lengths and counts.
func sanitize(r Result, devices map[string]bool) Result {
	switch strings.ToLower(strings.TrimSpace(r.Risk)) {
	case "hoch", "high":
		r.Risk = "hoch"
	case "niedrig", "low":
		r.Risk = "niedrig"
	default:
		r.Risk = "mittel"
	}
	r.Summary = clip(r.Summary, 1200)
	var pr []Priority
	for _, p := range r.Priorities {
		if strings.TrimSpace(p.Title) == "" {
			continue
		}
		p.Title, p.Why, p.Action, p.Severity = clip(p.Title, 160), clip(p.Why, 600), clip(p.Action, 600), severity(p.Severity)
		if !devices[p.DeviceID] {
			p.DeviceID = ""
		}
		pr = append(pr, p)
		if len(pr) == 6 {
			break
		}
	}
	r.Priorities = pr
	var fs []Finding
	seen := map[string]bool{}
	for _, f := range r.Findings {
		f.Slug = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(f.Slug)), "_"), "_")
		if len(f.Slug) > 40 {
			f.Slug = f.Slug[:40]
		}
		if f.Slug == "" || strings.TrimSpace(f.Title) == "" || !devices[f.DeviceID] || seen[f.DeviceID+"/"+f.Slug] {
			continue
		}
		seen[f.DeviceID+"/"+f.Slug] = true
		f.Title, f.Detail, f.Severity = clip(f.Title, 160), clip(f.Detail, 1000), severity(f.Severity)
		fs = append(fs, f)
		if len(fs) == 8 {
			break
		}
	}
	r.Findings = fs
	return r
}

func severity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "hoch":
		return "high"
	case "low", "niedrig":
		return "low"
	}
	return "medium"
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// RunNightly assesses every site with a box whose tenant has the switch on.
func (s *Service) RunNightly(ctx context.Context) {
	if _, err := s.provider(ctx); err != nil {
		return
	}
	tenants, err := s.Store.Tenants(ctx)
	if err != nil {
		return
	}
	for _, t := range tenants {
		if t.AIScope != store.AIScopeFacts {
			continue
		}
		sites, err := s.Store.Sites(ctx, t.ID)
		if err != nil {
			continue
		}
		for _, site := range sites {
			boxes, _ := s.Store.Boxes(ctx, site.ID)
			hasBox := false
			for _, b := range boxes {
				if b.RevokedAt == nil {
					hasBox = true
				}
			}
			if !hasBox {
				continue
			}
			if _, err := s.Assess(ctx, site.ID, "nightly"); err != nil {
				s.Log.Warn("ai: nightly", "site", site.ID, "err", err)
			}
		}
	}
}

// Run assesses every site once a day, early in the morning, local time.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := s.Now().In(s.Loc)
		day := now.Format("2006-01-02")
		if now.Hour() != nightlyHour || s.lastDay == day {
			continue
		}
		s.lastDay = day
		s.RunNightly(ctx)
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
