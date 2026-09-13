package console

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/excubra/excubra/internal/server/store"
)

// Getting onto a device should not mean selecting an address, copying it, opening
// a second window and typing a scheme and a port in front of it. This works out
// the ways in, and the console renders them as links.
//
// It is deliberately not a table of port numbers. A FortiGate's web interface
// sits on 443 at one customer, 8443 at the next and 10443 at the third, and a
// list of "ports that are usually https" is wrong at exactly the customer who
// moved it. What the scan knows is better evidence: a TLS handshake completed,
// and an HTML title came back. That is https, whatever the port says.

// wayIn is one protocol an operator's own client can open.
type wayIn struct {
	Kind string `json:"kind"` // https | http | ssh | rdp | vnc | smb | ftp
	Port int    `json:"port"`
	Note string `json:"note"` // why we think so, shown in the menu
}

// rank orders the ways by how likely an operator wants them.
var wayRank = map[string]int{"https": 0, "http": 1, "rdp": 2, "ssh": 3, "vnc": 4, "smb": 5, "ftp": 6}

// TLS on these ports is not a web interface, whatever else is true: linking
// https://host:993 opens a browser on an IMAP server and helps nobody.
var tlsNotWeb = map[int]bool{465: true, 636: true, 993: true, 995: true, 5061: true, 990: true, 2484: true}

// Devices that have a web interface even when nothing has scanned them yet. The
// guess is marked as one, so nobody reads a dead link as a broken device.
var webByKind = map[string]bool{"fw": true, "rt": true, "prn": true, "tel": true, "srv": true, "vm": true, "box": true}

// waysIn works out how to reach a device, best first. kind is the device's kind
// and is only used when nothing else is known.
func waysIn(svcs []store.Service, conns []store.Connector, kind string) []wayIn {
	var out []wayIn
	seen := map[string]bool{}
	// named "protocol", not "kind": the device's kind is a different thing and
	// shadowing it here would read as the same word meaning two things
	add := func(protocol string, port int, note string) {
		key := protocol + ":" + strconv.Itoa(port)
		if port <= 0 || port > 65535 || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, wayIn{Kind: protocol, Port: port, Note: note})
	}

	// An operator who configured a connector has already said where the interface
	// is, port and all. Nothing the scan guesses beats that.
	for _, c := range conns {
		u, err := url.Parse(strings.TrimSpace(c.URL))
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		port := defaultPort(u.Scheme)
		if p := u.Port(); p != "" {
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
		add(u.Scheme, port, "aus dem Konnektor")
	}

	for _, sv := range svcs {
		if sv.GoneAt != nil || (sv.Proto != "" && sv.Proto != "tcp") {
			continue
		}
		name := strings.ToLower(sv.Name)
		tls := len(sv.TLS) > 0 && string(sv.TLS) != "null"
		web := sv.Title != "" // a title only exists when something answered HTTP
		switch {
		case tls && (web || name == "https") && !tlsNotWeb[sv.Port]:
			note := "TLS erkannt"
			if web {
				note = "Weboberfläche erkannt"
			}
			add("https", sv.Port, note)
		case web || name == "http":
			add("http", sv.Port, "Weboberfläche erkannt")
		case name == "ssh":
			add("ssh", sv.Port, "Dienst erkannt")
		case name == "rdp":
			add("rdp", sv.Port, "Dienst erkannt")
		case name == "vnc":
			add("vnc", sv.Port, "Dienst erkannt")
		case name == "smb":
			add("smb", sv.Port, "Dienst erkannt")
		case name == "ftp":
			add("ftp", sv.Port, "Dienst erkannt")
		}
	}

	if len(out) == 0 && webByKind[kind] {
		add("https", 443, "nicht geprüft, üblich bei diesem Gerät")
		add("http", 80, "nicht geprüft, unverschlüsselt")
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := wayRank[a.Kind], wayRank[b.Kind]; ra != rb {
			return ra < rb
		}
		// the standard port of that protocol first, then the rest ascending
		sa, sb := a.Port == defaultPort(a.Kind), b.Port == defaultPort(b.Kind)
		if sa != sb {
			return sa
		}
		return a.Port < b.Port
	})
	return out
}

func defaultPort(kind string) int {
	switch kind {
	case "https":
		return 443
	case "http":
		return 80
	case "ssh":
		return 22
	case "rdp":
		return 3389
	case "vnc":
		return 5900
	case "smb":
		return 445
	case "ftp":
		return 21
	}
	return 0
}
