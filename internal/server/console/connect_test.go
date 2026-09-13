package console

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/store"
)

func svc(port int, name, title string, tls bool) store.Service {
	s := store.Service{Port: port, Proto: "tcp", Name: name, Title: title}
	if tls {
		s.TLS = json.RawMessage(`{"subject":"CN=x","version":"1.3"}`)
	}
	return s
}

// The case that started this: a FortiGate whose web interface does not sit on
// 443. A table of "ports that are usually https" is wrong at exactly the customer
// who moved it, so the evidence decides — a TLS handshake plus an HTML title is
// a web interface, whatever the port says.
func TestWaysInFindsHTTPSOnAnyPort(t *testing.T) {
	ways := waysIn([]store.Service{
		svc(10443, "", "FortiGate 60F", true), // moved admin port: no name, but TLS and a title
		svc(22, "ssh", "", false),
	}, nil, "fw")
	if len(ways) != 2 || ways[0].Kind != "https" || ways[0].Port != 10443 {
		t.Fatalf("the moved web interface should come first: %+v", ways)
	}
	if ways[0].Note == "" {
		t.Fatal("the menu should say why we think so")
	}
	if ways[1].Kind != "ssh" || ways[1].Port != 22 {
		t.Fatalf("ssh should follow: %+v", ways)
	}
}

func TestWaysIn(t *testing.T) {
	gone := time.Now()
	conns := []store.Connector{{URL: "https://192.0.2.1:8443/api"}, {URL: "  "}, {URL: "ssh://nope"}}
	svcs := []store.Service{
		svc(443, "https", "Anmeldung", true),
		svc(80, "http", "", false),
		svc(3389, "rdp", "", false),
		svc(5900, "vnc", "", false),
		svc(445, "smb", "", false),
		svc(21, "ftp", "", false),
		svc(993, "imaps", "", true),       // TLS, but linking a browser at IMAP helps nobody
		svc(9100, "jetdirect", "", false), // a printer's raw port is not a way in
		func() store.Service { s := svc(8080, "http", "", false); s.GoneAt = &gone; return s }(), // closed since
		func() store.Service { s := svc(161, "snmp", "", false); s.Proto = "udp"; return s }(),
	}
	ways := waysIn(svcs, conns, "fw")

	kinds := map[string][]int{}
	for _, w := range ways {
		kinds[w.Kind] = append(kinds[w.Kind], w.Port)
	}
	// the connector's port and the scanned one are both offered, standard first
	if got := kinds["https"]; len(got) != 2 || got[0] != 443 || got[1] != 8443 {
		t.Fatalf("https: %v", got)
	}
	if got := kinds["http"]; len(got) != 1 || got[0] != 80 {
		t.Fatalf("http should not include the port that closed: %v", got)
	}
	for _, unwanted := range []int{993, 9100, 161} {
		for _, w := range ways {
			if w.Port == unwanted {
				t.Fatalf("port %d should not be a way in: %+v", unwanted, w)
			}
		}
	}
	// order: https before http before rdp before ssh before vnc before smb before ftp
	var order []string
	for _, w := range ways {
		if len(order) == 0 || order[len(order)-1] != w.Kind {
			order = append(order, w.Kind)
		}
	}
	want := []string{"https", "http", "rdp", "vnc", "smb", "ftp"}
	if len(order) != len(want) {
		t.Fatalf("order %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order %v, want %v", order, want)
		}
	}
	if len(waysIn(nil, nil, "q")) != 0 {
		t.Fatal("nothing known, nothing offered")
	}
}
