package netbird

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientAgainstTheFake(t *testing.T) {
	fake := NewFake("tok")
	fake.Groups = []Group{{ID: "grp_viico", Name: "viico"}}
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	ctx := context.Background()

	bad := New(srv.URL, "wrong")
	if _, err := bad.Groups(ctx); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong token: %v", err)
	}
	c := New(srv.URL, "tok")
	g, err := c.EnsureGroup(ctx, "viico")
	if err != nil || g.ID != "grp_viico" {
		t.Fatalf("existing group: %+v %v", g, err)
	}
	lan, err := c.EnsureGroup(ctx, "kunden-lan")
	if err != nil || lan.ID == "" || len(fake.Groups) != 2 {
		t.Fatalf("new group: %+v %v", lan, err)
	}
	key, err := c.CreateSetupKey(ctx, "ex0 muster", []string{lan.ID}, time.Hour)
	if err != nil || !strings.HasPrefix(key.Key, "SETUP-") {
		t.Fatalf("setup key: %+v %v", key, err)
	}
	n, err := c.CreateNetwork(ctx, "Muster · Werk", "managed by EX0")
	if err != nil || n.ID == "" {
		t.Fatal(err)
	}
	res, err := c.CreateResource(ctx, n.ID, "Werk LAN", "192.168.10.0/24", []string{lan.ID}, true)
	if err != nil || res.Address != "192.168.10.0/24" {
		t.Fatalf("resource: %+v %v", res, err)
	}
	if _, err := c.CreateRouter(ctx, n.ID, "peer_1", true, 100); err != nil {
		t.Fatal(err)
	}
	pol, err := c.EnsurePolicy(ctx, "ex0: viico → kunden-lan", []string{g.ID}, []string{lan.ID})
	if err != nil || pol.ID == "" {
		t.Fatal(err)
	}
	if pol2, _ := c.EnsurePolicy(ctx, "ex0: viico → kunden-lan", nil, nil); pol2.ID != pol.ID {
		t.Fatal("policy created twice")
	}
	if err := c.SetResourceEnabled(ctx, n.ID, res.ID, res.Name, res.Address, []string{lan.ID}, false); err != nil {
		t.Fatal(err)
	}
	if fake.Res[n.ID][0].Enabled {
		t.Fatal("resource still enabled")
	}
	if err := c.DeleteNetwork(ctx, n.ID); err != nil || len(fake.Networks) != 0 {
		t.Fatalf("delete: %v", err)
	}
}
