package console

// Connectors (ADR-0015): the device page lists them, the browser seals the
// credential to the box, the box reads the device and the readings land here.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/seal"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// connectorLabels are the German names of the closed connector list.
var connectorLabels = map[string]string{wire.ConnectorFortiGate: "FortiGate", wire.ConnectorStarface: "STARFACE"}

// ConnectorLabel names a kind for people.
func ConnectorLabel(kind string) string {
	if l, ok := connectorLabels[kind]; ok {
		return l
	}
	return kind
}

// connectorView is a connector without its ciphertext.
type connectorView struct {
	ID              string             `json:"id"`
	DeviceID        string             `json:"deviceId"`
	Kind            string             `json:"kind"`
	KindLabel       string             `json:"kindLabel"`
	URL             string             `json:"url"`
	SealedBy        string             `json:"sealedBy"`
	SealedAt        time.Time          `json:"sealedAt"`
	IntervalS       int                `json:"intervalS"`
	TLSFingerprint  string             `json:"tlsFingerprint"`
	SeenFingerprint string             `json:"seenFingerprint"`
	Disabled        bool               `json:"disabled"`
	LastOK          *bool              `json:"lastOk"`
	LastError       string             `json:"lastError"`
	LastAt          *time.Time         `json:"lastAt"`
	Facts           json.RawMessage    `json:"facts"`
	FactsAt         *time.Time         `json:"factsAt"`
	Metrics         map[string]float64 `json:"metrics"`
	Class           string             `json:"class"` // ok | failed | paused | pending
}

func viewConnector(c store.Connector) connectorView {
	v := connectorView{ID: c.ID, DeviceID: c.DeviceID, Kind: c.Kind, KindLabel: ConnectorLabel(c.Kind), URL: c.URL, SealedBy: strings.TrimPrefix(c.SealedBy, "console:"), SealedAt: c.SealedAt,
		IntervalS: c.IntervalS, TLSFingerprint: c.TLSFingerprint, SeenFingerprint: c.SeenFingerprint, Disabled: c.Disabled, LastOK: c.LastOK, LastError: c.LastError, LastAt: c.LastAt,
		Facts: c.Facts, FactsAt: c.FactsAt, Metrics: c.Metrics}
	if len(v.Facts) == 0 {
		v.Facts = json.RawMessage("{}")
	}
	if v.Metrics == nil {
		v.Metrics = map[string]float64{}
	}
	switch {
	case c.Disabled:
		v.Class = "paused"
	case c.LastOK == nil:
		v.Class = "pending"
	case *c.LastOK:
		v.Class = "ok"
	default:
		v.Class = "failed"
	}
	return v
}

// deviceConnectors feeds the connector tab of a device page.
type deviceConnectors struct {
	Box         *boxRow         `json:"box"` // the site's box, nil when the site has none
	SealKey     string          `json:"sealKey"`
	Fingerprint string          `json:"fingerprint"`
	Online      bool            `json:"online"`
	Kinds       []kindOption    `json:"kinds"`
	Connectors  []connectorView `json:"connectors"`
}

type kindOption struct {
	Kind   string     `json:"kind"`
	Label  string     `json:"label"`
	Fields []string   `json:"fields"` // what the credential document needs
	Modes  []kindMode `json:"modes,omitempty"`
}

// kindMode is an alternative credential document for a kind.
type kindMode struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Hint   string   `json:"hint"`
	Fields []string `json:"fields"`
}

var kindOptions = []kindOption{
	{Kind: wire.ConnectorFortiGate, Label: "FortiGate", Fields: []string{"token"}, Modes: []kindMode{
		{ID: "bootstrap", Label: "Admin-Zugang, EX0 legt den API-Benutzer selbst an", Hint: "Die Box meldet sich einmal als Administrator an, legt Profil „excubra-ro“ (nur lesen) und API-Benutzer „excubra“ mit Trusted Host = Box an, erzeugt den Token und meldet ihn versiegelt zurück. Der Admin-Zugang wird danach auf dem Server gelöscht.", Fields: []string{"admin_user", "admin_password"}},
		{ID: "token", Label: "Vorhandener API-Token", Hint: "REST-API-Admin auf der FortiGate mit Leserechten, Trusted Host = Adresse der Box.", Fields: []string{"token"}},
	}},
	{Kind: wire.ConnectorStarface, Label: "STARFACE", Fields: []string{"user", "password"}},
}

func (s *Server) siteBox(ctx context.Context, siteID string) (*store.Box, error) {
	boxes, err := s.Store.Boxes(ctx, siteID)
	if err != nil {
		return nil, err
	}
	for _, b := range boxes {
		if b.RevokedAt == nil {
			b := b
			return &b, nil
		}
	}
	return nil, nil //nolint:nilnil // no box is a normal state
}

func (s *Server) apiDeviceConnectors(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dev, err := s.Store.Device(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	d := deviceConnectors{Kinds: kindOptions, Connectors: []connectorView{}}
	box, err := s.siteBox(ctx, dev.SiteID)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	if box != nil {
		tm, sm, err := s.lookups(ctx)
		if err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		row := s.boxRow(*box, sm, tm)
		d.Box = &row
		d.SealKey = box.SealKey
		d.Fingerprint = seal.Fingerprint(box.SealKey)
		d.Online = row.State.Status != "silent" && !row.State.LastHeartbeat.IsZero()
	}
	cons, err := s.Store.ConnectorsForDevice(ctx, dev.ID)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	for _, c := range cons {
		d.Connectors = append(d.Connectors, viewConnector(c))
	}
	writeJSON(w, http.StatusOK, d)
}

// connectorCreate stores a sealed credential for a device. The browser did the
// sealing; this handler never sees a token.
func (s *Server) connectorCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dev, err := s.Store.Device(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	back := "/devices/" + dev.ID + "?tab=konnektor"
	kind := r.PostForm.Get("kind")
	if !wire.ValidConnectorKind(kind) {
		s.flashErr(w, r, "Unbekannte Konnektor-Art.", back)
		return
	}
	u, ok := cleanDeviceURL(r.PostForm.Get("url"))
	if !ok {
		s.flashErr(w, r, "Adresse muss https://host oder http://host sein, ohne Pfad.", back)
		return
	}
	sealed := strings.TrimSpace(r.PostForm.Get("sealed"))
	if len(sealed) < 80 || len(sealed) > 16*1024 {
		s.flashErr(w, r, "Versiegelte Zugangsdaten fehlen; der Browser muss sie für die Box versiegeln.", back)
		return
	}
	box, err := s.siteBox(ctx, dev.SiteID)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	if box == nil {
		s.flashErr(w, r, "Diesem Standort ist keine Box zugeordnet; ohne Box liest niemand das Gerät.", back)
		return
	}
	if box.SealKey == "" {
		s.flashErr(w, r, "Die Box hat noch keinen Siegelschlüssel gemeldet; sie braucht ein Update auf den aktuellen Agent.", back)
		return
	}
	interval := 300
	if v, err := strconv.Atoi(r.PostForm.Get("interval_s")); err == nil && v >= 60 && v <= 3600 {
		interval = v
	}
	now := s.Now()
	c := store.Connector{ID: id.New("con"), TenantID: dev.TenantID, SiteID: dev.SiteID, BoxID: box.ID, DeviceID: dev.ID, Kind: kind, URL: u, Sealed: sealed,
		SealedBy: actor(r), SealedAt: now, IntervalS: interval, TLSFingerprint: cleanFingerprint(r.PostForm.Get("tls_fingerprint")), CreatedAt: now}
	if err := s.Store.CreateConnector(ctx, c); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, now, actor(r), "connector.create", c.ID, ConnectorLabel(kind)+" "+u+" for "+dev.ID)
	s.flash(w, r, ConnectorLabel(kind)+" verbunden. Die Box liest das Gerät mit dem nächsten Config-Pull, das erste Ergebnis kommt in ein bis zwei Minuten.", back)
}

// connectorSecret replaces credential, address, interval or pin.
func (s *Server) connectorSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.Store.Connector(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	back := "/devices/" + c.DeviceID + "?tab=konnektor"
	u, ok := cleanDeviceURL(r.PostForm.Get("url"))
	if !ok {
		u = c.URL
	}
	sealed := strings.TrimSpace(r.PostForm.Get("sealed"))
	if sealed == "" {
		sealed = c.Sealed
	} else if len(sealed) < 80 || len(sealed) > 16*1024 {
		s.flashErr(w, r, "Versiegelte Zugangsdaten sind unbrauchbar.", back)
		return
	}
	interval := c.IntervalS
	if v, err := strconv.Atoi(r.PostForm.Get("interval_s")); err == nil && v >= 60 && v <= 3600 {
		interval = v
	}
	fp := c.TLSFingerprint
	if _, given := r.PostForm["tls_fingerprint"]; given {
		fp = cleanFingerprint(r.PostForm.Get("tls_fingerprint"))
	}
	by := c.SealedBy
	if sealed != c.Sealed {
		by = actor(r)
	}
	if err := s.Store.UpdateConnectorSecret(ctx, c.ID, u, sealed, by, fp, interval, s.Now()); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "connector.update", c.ID, u)
	s.flash(w, r, "Gespeichert; die Box liest mit dem nächsten Config-Pull neu.", back)
}

// connectorPin pins the certificate the box last saw.
func (s *Server) connectorPin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.Store.Connector(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	back := "/devices/" + c.DeviceID + "?tab=konnektor"
	if c.SeenFingerprint == "" {
		s.flashErr(w, r, "Die Box hat noch kein Zertifikat dieses Geräts gesehen.", back)
		return
	}
	if err := s.Store.UpdateConnectorSecret(ctx, c.ID, c.URL, c.Sealed, c.SealedBy, c.SeenFingerprint, c.IntervalS, c.SealedAt); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "connector.pin", c.ID, c.SeenFingerprint)
	s.flash(w, r, "Zertifikat festgenagelt: ein anderes Zertifikat lässt die Prüfung ab jetzt fehlschlagen.", back)
}

func (s *Server) connectorToggle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.Store.Connector(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	back := "/devices/" + c.DeviceID + "?tab=konnektor"
	if err := s.Store.SetConnectorDisabled(ctx, c.ID, !c.Disabled); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	if !c.Disabled {
		s.closeFindings(ctx, c.ID)
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "connector.toggle", c.ID, strconv.FormatBool(!c.Disabled))
	if c.Disabled {
		s.flash(w, r, "Konnektor wieder aktiv.", back)
		return
	}
	s.flash(w, r, "Konnektor pausiert; die Box liest das Gerät nicht mehr.", back)
}

func (s *Server) connectorDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.Store.Connector(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	back := "/devices/" + c.DeviceID + "?tab=konnektor"
	if err := s.Store.DeleteConnector(ctx, c.ID); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	s.closeFindings(ctx, c.ID)
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "connector.delete", c.ID, ConnectorLabel(c.Kind)+" "+c.URL)
	s.flash(w, r, "Konnektor entfernt; die versiegelten Zugangsdaten sind gelöscht.", back)
}

// apiConnectorSamples returns one metric over a range for the chart.
func (s *Server) apiConnectorSamples(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.Store.Connector(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		s.fail(w, r, errBadKey, http.StatusBadRequest)
		return
	}
	now := s.Now()
	from := now.Add(-24 * time.Hour)
	if r.URL.Query().Get("range") == "7d" {
		from = now.Add(-7 * 24 * time.Hour)
	}
	samples, err := s.Store.ConnectorSamples(ctx, c.TenantID, c.ID, key, from, now)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	type point struct {
		At    time.Time `json:"at"`
		Value float64   `json:"value"`
	}
	out := make([]point, 0, len(samples))
	for _, smp := range samples {
		out = append(out, point{At: smp.At, Value: smp.Value})
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "points": out})
}

// cleanDeviceURL accepts scheme://host[:port] and nothing else.
func cleanDeviceURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

// cleanFingerprint normalises a sha256 hex fingerprint (colons allowed) or returns "".
func cleanFingerprint(raw string) string {
	raw = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), ":", ""))
	if len(raw) != 64 {
		return ""
	}
	for _, ch := range raw {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return ""
		}
	}
	return raw
}

var errBadKey = errBadRequest("key fehlt")

type errBadRequest string

func (e errBadRequest) Error() string { return string(e) }

// closeFindings resolves a connector's findings and drops their acknowledgements.
func (s *Server) closeFindings(ctx context.Context, connectorID string) {
	ids, err := s.Store.ResolveConnectorFindings(ctx, connectorID, s.Now())
	if err != nil {
		s.Log.Error("resolve findings", "connector", connectorID, "err", err)
		return
	}
	for _, id := range ids {
		_ = s.Store.DeleteAck(ctx, "finding", id)
	}
}
