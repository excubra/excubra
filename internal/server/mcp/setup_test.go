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
	s := &Server{Store: st, Now: func() time.Time { return now }, Actor: "jeremia", CAFingerprint: ca.Fingerprint(), Ingest: "ingest.example.test", IngestPt: 443}

	// the customer
	out, err := s.call(ctx, "ex0_create_tenant", map[string]any{"slug": "MUSTER", "name": " Kanzlei Muster "})
	must(t, err)
	var ten map[string]any
	must(t, json.Unmarshal([]byte(out), &ten))
	if ten["tenant_id"] != "ten_muster" || ten["name"] != "Kanzlei Muster" {
		t.Fatalf("tenant: %s", out)
	}
	if _, err := s.call(ctx, "ex0_create_tenant", map[string]any{"slug": "muster", "name": "noch mal"}); err == nil {
		t.Fatal("a second customer with the same slug must be refused, not silently replaced")
	}
	if _, err := s.call(ctx, "ex0_create_tenant", map[string]any{"slug": "Kanzlei MUSTER", "name": "x"}); err == nil {
		t.Fatal("a slug with a space is not a slug")
	}

	// the site, without an address: no network in a test, and no address is a
	// valid state (the site is only missing from the map)
	out, err = s.call(ctx, "ex0_create_site", map[string]any{"tenant_id": "ten_muster", "slug": "kanzlei", "name": "Kanzlei"})
	must(t, err)
	var site map[string]any
	must(t, json.Unmarshal([]byte(out), &site))
	if site["site_id"] != "site_kanzlei" || !strings.Contains(out, "ohne Adresse") {
		t.Fatalf("site: %s", out)
	}
	stored, err := st.Site(ctx, "site_kanzlei")
	must(t, err)
	if stored.TenantID != "ten_muster" || stored.Located {
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
	if box.Hostname != "ex0-muster-kanzlei" {
		t.Fatalf("the hostname is made of the two slugs, not of the display names: %q", box.Hostname)
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
	// a download is a file first and a run second; piped into a shell, a failed
	// download is an empty script that ends quietly
	if strings.Contains(box.Commands[0].Cmd, "| bash") || !strings.Contains(box.Commands[0].Cmd, "-o /tmp/ex0-box-pct.sh && bash /tmp/ex0-box-pct.sh --enroll-key") {
		t.Fatalf("the command must load, then run: %s", box.Commands[0].Cmd)
	}
	if !strings.Contains(out, "ssh_keys") {
		t.Fatalf("a box nobody can log in to deserves a warning: %s", out)
	}

	// What the session knows about the container is in the command, so nobody
	// appends anything by hand — and the technicians' keys are in both.
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlvZi4wdGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleQ jeremia@mac"
	out, err = s.call(ctx, "ex0_new_box", map[string]any{"site_id": "site_kanzlei", "ctid": float64(200), "bridge": "vmbr0", "ip": "192.0.2.60/24", "gw": "192.0.2.111",
		"storage": "local-zfs", "disk": float64(8), "memory": float64(1024), "ssh_keys": []any{key}})
	must(t, err)
	must(t, json.Unmarshal([]byte(out), &box))
	for _, want := range []string{"--ctid 200", "--bridge vmbr0", "--ip 192.0.2.60/24 --gw 192.0.2.111", "--storage local-zfs", "--disk 8", "--memory 1024", "--ssh-key '" + key + "'"} {
		if !strings.Contains(box.Commands[0].Cmd, want) {
			t.Fatalf("the proxmox command misses %q: %s", want, box.Commands[0].Cmd)
		}
	}
	if strings.Contains(box.Commands[1].Cmd, "--ctid") || !strings.Contains(box.Commands[1].Cmd, "--ssh-key '"+key+"'") {
		t.Fatalf("a machine of its own takes the keys, not the container values: %s", box.Commands[1].Cmd)
	}
	if strings.Contains(out, "\"warning\"") {
		t.Fatalf("with a key there is nothing to warn about: %s", out)
	}
	// nothing that a shell would read as more than a value
	for _, bad := range []map[string]any{
		{"site_id": "site_kanzlei", "bridge": "vmbr0; rm -rf /"},
		{"site_id": "site_kanzlei", "storage": "$(reboot)"},
		{"site_id": "site_kanzlei", "ip": "192.0.2.60/24"},                             // a fixed address without its gateway
		{"site_id": "site_kanzlei", "ip": "192.0.2.60/24", "gw": "192.168.1.1"},        // a gateway from another network
		{"site_id": "site_kanzlei", "ip": "192.0.2.0/24", "gw": "192.0.2.111"},         // the network, not an address
		{"site_id": "site_kanzlei", "ssh_keys": []any{"ssh-ed25519 AAAA' ; reboot '"}}, // a quote would end the argument
		{"site_id": "site_kanzlei", "ssh_keys": []any{"-----BEGIN OPENSSH PRIVATE KEY-----"}},
		{"site_id": "site_kanzlei", "ctid": float64(5)},
	} {
		if _, err := s.call(ctx, "ex0_new_box", bad); err == nil {
			t.Fatalf("must be refused: %v", bad)
		}
	}
	if keys, _ := st.EnrollmentKeys(ctx); len(keys) != 2 {
		t.Fatalf("a refused call must not leave a key behind: %d keys", len(keys))
	}

	// a server started without CA and ingest refuses this one tool, loudly
	bare := &Server{Store: st, Now: s.Now, Actor: "jeremia"}
	if _, err := bare.call(ctx, "ex0_new_box", map[string]any{"site_id": "site_kanzlei"}); err == nil || !strings.Contains(err.Error(), "CA") {
		t.Fatalf("without CA: %v", err)
	}
}
