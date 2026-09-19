package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/store"
)

// A session sets a customer up end to end without a person clicking anything:
// tenant, site, key with the one-liners. What it gets back is what the console
// would have shown, and what is stored is what the console would have stored.
func TestSetupWithoutAPerson(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ca, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	s := &Server{Store: st, Now: func() time.Time { return now }, Actor: "jeremia", CA: ca, Ingest: "ingest.example.test", IngestPt: 443}

	// the customer
	out, err := s.call(ctx, "ex0_create_tenant", map[string]any{"slug": "SRAS", "name": " Rechtsanwaltskanzlei SRAS "})
	must(t, err)
	var ten map[string]any
	must(t, json.Unmarshal([]byte(out), &ten))
	if ten["tenant_id"] != "ten_sras" || ten["name"] != "Rechtsanwaltskanzlei SRAS" {
		t.Fatalf("tenant: %s", out)
	}
	if _, err := s.call(ctx, "ex0_create_tenant", map[string]any{"slug": "sras", "name": "noch mal"}); err == nil {
		t.Fatal("a second customer with the same slug must be refused, not silently replaced")
	}
	if _, err := s.call(ctx, "ex0_create_tenant", map[string]any{"slug": "Kanzlei SRAS", "name": "x"}); err == nil {
		t.Fatal("a slug with a space is not a slug")
	}

	// the site, without an address: no network in a test, and no address is a
	// valid state (the site is only missing from the map)
	out, err = s.call(ctx, "ex0_create_site", map[string]any{"tenant_id": "ten_sras", "slug": "kanzlei", "name": "Kanzlei"})
	must(t, err)
	var site map[string]any
	must(t, json.Unmarshal([]byte(out), &site))
	if site["site_id"] != "site_kanzlei" || !strings.Contains(out, "ohne Adresse") {
		t.Fatalf("site: %s", out)
	}
	stored, err := st.Site(ctx, "site_kanzlei")
	must(t, err)
	if stored.TenantID != "ten_sras" || stored.Located {
		t.Fatalf("stored site: %+v", stored)
	}
	if _, err := s.call(ctx, "ex0_create_site", map[string]any{"tenant_id": "ten_niemand", "slug": "x", "name": "x"}); err == nil {
		t.Fatal("a site needs an existing customer")
	}

	// the key and the one-liners
	out, err = s.call(ctx, "ex0_new_box", map[string]any{"site_id": "site_kanzlei", "note": "Container auf dem Kunden-Proxmox", "expires_days": float64(30)})
	must(t, err)
	var box struct {
		KeyID    string `json:"key_id"`
		Hostname string `json:"hostname"`
		Commands []struct{ Title, Cmd string }
	}
	must(t, json.Unmarshal([]byte(out), &box))
	if box.Hostname != "ex0-rechtsanwaltskanzlei-sras-kanzlei" {
		t.Fatalf("hostname: %q", box.Hostname)
	}
	if len(box.Commands) != 2 || !strings.Contains(box.Commands[0].Cmd, "ex0-box-pct.sh") || !strings.Contains(box.Commands[1].Cmd, "ex0-box.sh") {
		t.Fatalf("commands: %+v", box.Commands)
	}
	if !strings.Contains(box.Commands[0].Cmd, "--enroll-key 'EX0:") || !strings.Contains(box.Commands[0].Cmd, "--hostname "+box.Hostname) {
		t.Fatalf("the proxmox one-liner must carry key and hostname: %s", box.Commands[0].Cmd)
	}
	keys, err := st.EnrollmentKeys(ctx)
	must(t, err)
	if len(keys) != 1 || keys[0].ID != box.KeyID || keys[0].SiteID != "site_kanzlei" || keys[0].Note != "Container auf dem Kunden-Proxmox" {
		t.Fatalf("the key must be bound to the site, like the console binds it: %+v", keys)
	}
	if !keys[0].ExpiresAt.Equal(now.Add(30 * 24 * time.Hour)) {
		t.Fatalf("expiry: %v", keys[0].ExpiresAt)
	}
	// the secret is in the command and nowhere in the store
	if strings.Contains(keys[0].SecretHash, "EX0:") {
		t.Fatal("the store keeps a hash, never the key")
	}
	if _, err := s.call(ctx, "ex0_new_box", map[string]any{"site_id": "site_gibt_es_nicht"}); err == nil {
		t.Fatal("a key for a site that does not exist would be a box nobody can place")
	}

	// a server started without CA and ingest refuses this one tool, loudly
	bare := &Server{Store: st, Now: s.Now, Actor: "jeremia"}
	if _, err := bare.call(ctx, "ex0_new_box", map[string]any{"site_id": "site_kanzlei"}); err == nil || !strings.Contains(err.Error(), "CA") {
		t.Fatalf("without CA: %v", err)
	}
}
