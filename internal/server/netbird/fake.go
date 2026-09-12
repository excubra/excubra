package netbird

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Fake is a minimal NetBird management API for tests: groups, keys, peers,
// networks with resources and routers, policies. Exported for other packages' tests.
type Fake struct {
	Token    string
	Groups   []Group
	Peers    []Peer
	Networks []Network
	Res      map[string][]Resource
	Routers  map[string][]Router
	Policies []Policy
	Keys     []SetupKey
	Calls    []string
	n        int
}

func NewFake(token string) *Fake {
	return &Fake{Token: token, Res: map[string][]Resource{}, Routers: map[string][]Router{}}
}

func (f *Fake) id(prefix string) string {
	f.n++
	return prefix + strings.Repeat("0", 2) + string(rune('a'+f.n%26)) + itoa(f.n)
}

func itoa(n int) string { return strings.TrimLeft(strings.Repeat(" ", 0)+fmtInt(n), " ") }

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func (f *Fake) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.Calls = append(f.Calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Token "+f.Token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		p := strings.TrimPrefix(r.URL.Path, "/api/")
		parts := strings.Split(p, "/")
		switch {
		case p == "groups" && r.Method == "GET":
			_ = json.NewEncoder(w).Encode(f.Groups)
		case p == "groups" && r.Method == "POST":
			g := Group{ID: f.id("grp"), Name: body["name"].(string)}
			f.Groups = append(f.Groups, g)
			_ = json.NewEncoder(w).Encode(g)
		case p == "setup-keys" && r.Method == "POST":
			k := SetupKey{ID: f.id("key"), Key: "SETUP-" + f.id("K"), Name: body["name"].(string), Valid: true, Expires: time.Now().Add(time.Hour)}
			f.Keys = append(f.Keys, k)
			_ = json.NewEncoder(w).Encode(k)
		case p == "peers" && r.Method == "GET":
			_ = json.NewEncoder(w).Encode(f.Peers)
		case p == "networks" && r.Method == "GET":
			_ = json.NewEncoder(w).Encode(f.Networks)
		case p == "networks" && r.Method == "POST":
			n := Network{ID: f.id("net"), Name: body["name"].(string)}
			f.Networks = append(f.Networks, n)
			_ = json.NewEncoder(w).Encode(n)
		case len(parts) == 2 && parts[0] == "networks" && r.Method == "DELETE":
			var keep []Network
			for _, n := range f.Networks {
				if n.ID != parts[1] {
					keep = append(keep, n)
				}
			}
			f.Networks = keep
			w.WriteHeader(200)
		case len(parts) == 3 && parts[0] == "networks" && parts[2] == "resources" && r.Method == "GET":
			res := f.Res[parts[1]]
			if res == nil {
				res = []Resource{}
			}
			_ = json.NewEncoder(w).Encode(res)
		case len(parts) == 3 && parts[0] == "networks" && parts[2] == "resources" && r.Method == "POST":
			res := Resource{ID: f.id("res"), Name: body["name"].(string), Address: body["address"].(string), Enabled: body["enabled"].(bool)}
			f.Res[parts[1]] = append(f.Res[parts[1]], res)
			_ = json.NewEncoder(w).Encode(res)
		case len(parts) == 4 && parts[0] == "networks" && parts[2] == "resources" && r.Method == "PUT":
			for i, res := range f.Res[parts[1]] {
				if res.ID == parts[3] {
					f.Res[parts[1]][i].Enabled = body["enabled"].(bool)
				}
			}
			w.WriteHeader(200)
		case len(parts) == 3 && parts[0] == "networks" && parts[2] == "routers" && r.Method == "POST":
			rt := Router{ID: f.id("rtr"), Peer: body["peer"].(string), Masquerade: body["masquerade"].(bool), Enabled: true}
			f.Routers[parts[1]] = append(f.Routers[parts[1]], rt)
			_ = json.NewEncoder(w).Encode(rt)
		case p == "policies" && r.Method == "GET":
			_ = json.NewEncoder(w).Encode(f.Policies)
		case p == "policies" && r.Method == "POST":
			pol := Policy{ID: f.id("pol"), Name: body["name"].(string), Enabled: true}
			f.Policies = append(f.Policies, pol)
			_ = json.NewEncoder(w).Encode(pol)
		default:
			w.WriteHeader(404)
		}
	})
}
