package connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// fortigate reads a FortiGate through the FortiOS REST API with an API-user token
// (Authorization: Bearer). Only monitor and read-only CMDB endpoints. The sealed
// credential is {"token": "…"}.
//
// Everything after system/status is optional: a FortiOS version that lacks an
// endpoint costs a line in facts.problems, not the whole reading.
type fortigate struct{}

func (fortigate) Read(ctx context.Context, t Target) (Reading, error) {
	var cred struct {
		Token         string `json:"token"`
		AdminUser     string `json:"admin_user"`
		AdminPassword string `json:"admin_password"`
	}
	if err := json.Unmarshal(t.Secret, &cred); err != nil {
		return Reading{}, errors.New("credential is not readable")
	}
	var reading Reading
	if strings.TrimSpace(cred.Token) == "" {
		if cred.AdminUser == "" || cred.AdminPassword == "" {
			return Reading{}, errors.New("credential needs a token, or an admin login for the bootstrap")
		}
		token, err := fortigateBootstrap(ctx, t, cred.AdminUser, cred.AdminPassword)
		if err != nil {
			return Reading{}, fmt.Errorf("bootstrap: %w", err)
		}
		cred.Token = token
		reading.NewToken, _ = json.Marshal(map[string]string{"token": token})
	}
	base := strings.TrimRight(t.URL, "/")
	hdr := map[string]string{"Authorization": "Bearer " + strings.TrimSpace(cred.Token)}
	get := func(path string, out any) error { return getJSON(ctx, t.Client, base+path, hdr, out) }
	facts := map[string]any{}
	metrics := map[string]float64{}
	var problems []string
	optional := func(what string, err error) {
		if err != nil {
			problems = append(problems, what+": "+err.Error())
		}
	}

	// status: the envelope of every monitor answer carries serial, version and build
	var st struct {
		Serial  string `json:"serial"`
		Version string `json:"version"`
		Build   int    `json:"build"`
		Results struct {
			Hostname      string `json:"hostname"`
			Model         string `json:"model"`
			ModelName     string `json:"model_name"`
			ModelNumber   string `json:"model_number"`
			LogDiskStatus string `json:"log_disk_status"`
		} `json:"results"`
	}
	if err := get("/api/v2/monitor/system/status", &st); err != nil {
		return Reading{}, err
	}
	facts["serial"] = st.Serial
	facts["version"] = st.Version
	facts["build"] = st.Build
	facts["hostname"] = st.Results.Hostname
	facts["model"] = strings.TrimSpace(st.Results.ModelName + " " + st.Results.ModelNumber)
	if facts["model"] == "" {
		facts["model"] = st.Results.Model
	}
	facts["log_disk"] = st.Results.LogDiskStatus

	// resources
	var ru struct {
		Results struct {
			CPU []struct {
				Current float64 `json:"current"`
			} `json:"cpu"`
			Mem []struct {
				Current float64 `json:"current"`
			} `json:"mem"`
			Session []struct {
				Current float64 `json:"current"`
			} `json:"session"`
			Disk []struct {
				Current float64 `json:"current"`
			} `json:"disk"`
		} `json:"results"`
	}
	if err := get("/api/v2/monitor/system/resource/usage?interval=1-min", &ru); err == nil {
		if len(ru.Results.CPU) > 0 {
			metrics["cpu_pct"] = ru.Results.CPU[0].Current
		}
		if len(ru.Results.Mem) > 0 {
			metrics["mem_pct"] = ru.Results.Mem[0].Current
		}
		if len(ru.Results.Session) > 0 {
			metrics["sessions"] = ru.Results.Session[0].Current
		}
		if len(ru.Results.Disk) > 0 {
			metrics["disk_pct"] = ru.Results.Disk[0].Current
		}
	} else {
		optional("resource usage", err)
	}

	// interface configuration: role and which management protocols each one allows
	type ifCfg struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		AllowAccess string `json:"allowaccess"`
		Status      string `json:"status"`
		Type        string `json:"type"`
	}
	var ifc struct {
		Results []ifCfg `json:"results"`
	}
	cfgByName := map[string]ifCfg{}
	if err := get("/api/v2/cmdb/system/interface", &ifc); err == nil {
		for _, c := range ifc.Results {
			cfgByName[c.Name] = c
		}
	} else {
		optional("interface config", err)
	}

	// interfaces
	var ifs struct {
		Results map[string]struct {
			Name    string  `json:"name"`
			Alias   string  `json:"alias"`
			Link    bool    `json:"link"`
			Speed   float64 `json:"speed"`
			IP      string  `json:"ip"`
			RxBytes float64 `json:"rx_bytes"`
			TxBytes float64 `json:"tx_bytes"`
		} `json:"results"`
	}
	if err := get("/api/v2/monitor/system/interface?include_vlan=true", &ifs); err == nil {
		var list []map[string]any
		up, down := 0, 0
		for name, i := range ifs.Results {
			if i.Name == "" {
				i.Name = name
			}
			if i.Link {
				up++
			} else {
				down++
			}
			entry := map[string]any{"name": i.Name, "alias": i.Alias, "link": i.Link, "ip": i.IP, "speed": i.Speed, "rx_bytes": i.RxBytes, "tx_bytes": i.TxBytes}
			if c, ok := cfgByName[i.Name]; ok {
				entry["role"] = c.Role
				entry["admin"] = c.AllowAccess
				entry["type"] = c.Type
				if c.Status != "" {
					entry["enabled"] = c.Status == "up"
				}
			}
			list = append(list, entry)
		}
		sort.Slice(list, func(a, b int) bool { return list[a]["name"].(string) < list[b]["name"].(string) })
		facts["interfaces"] = list
		metrics["interfaces_up"] = float64(up)
		metrics["interfaces_down"] = float64(down)
	} else {
		optional("interfaces", err)
	}

	// IPsec tunnels
	var vpn struct {
		Results []struct {
			Name     string `json:"name"`
			Comments string `json:"comments"`
			Rgwy     string `json:"rgwy"`
			Proxyid  []struct {
				P2name   string  `json:"p2name"`
				Status   string  `json:"status"`
				Incoming float64 `json:"incoming_bytes"`
				Outgoing float64 `json:"outgoing_bytes"`
			} `json:"proxyid"`
		} `json:"results"`
	}
	if err := get("/api/v2/monitor/vpn/ipsec", &vpn); err == nil {
		var list []map[string]any
		up, down := 0, 0
		for _, tun := range vpn.Results {
			anyUp := false
			var p2 []map[string]any
			for _, p := range tun.Proxyid {
				if p.Status == "up" {
					anyUp = true
				}
				p2 = append(p2, map[string]any{"name": p.P2name, "status": p.Status, "in_bytes": p.Incoming, "out_bytes": p.Outgoing})
			}
			if anyUp {
				up++
			} else {
				down++
			}
			list = append(list, map[string]any{"name": tun.Name, "gateway": tun.Rgwy, "comment": tun.Comments, "up": anyUp, "phase2": p2})
		}
		facts["ipsec"] = list
		metrics["ipsec_up"] = float64(up)
		metrics["ipsec_down"] = float64(down)
	} else {
		optional("ipsec", err)
	}

	// HA
	var ha struct {
		Results struct {
			Mode      string `json:"mode"`
			GroupName string `json:"group-name"`
		} `json:"results"`
	}
	if err := get("/api/v2/cmdb/system/ha", &ha); err == nil {
		facts["ha_mode"] = ha.Results.Mode
		if ha.Results.Mode != "" && ha.Results.Mode != "standalone" {
			facts["ha_group"] = ha.Results.GroupName
			var peers struct {
				Results []struct {
					Serial   string `json:"serial_no"`
					Hostname string `json:"hostname"`
					Priority int    `json:"priority"`
					Primary  bool   `json:"master"`
				} `json:"results"`
			}
			if err := get("/api/v2/monitor/system/ha-peer", &peers); err == nil {
				var list []map[string]any
				for _, p := range peers.Results {
					list = append(list, map[string]any{"serial": p.Serial, "hostname": p.Hostname, "priority": p.Priority, "primary": p.Primary})
				}
				facts["ha_peers"] = list
				metrics["ha_peers"] = float64(len(list))
			} else {
				optional("ha peers", err)
			}
		}
	} else {
		optional("ha", err)
	}

	// licenses
	var lic struct {
		Results map[string]struct {
			Status  string  `json:"status"`
			Expires float64 `json:"expires"`
		} `json:"results"`
	}
	if err := get("/api/v2/monitor/license/status", &lic); err == nil {
		out := map[string]any{}
		expired := 0
		for k, v := range lic.Results {
			entry := map[string]any{"status": v.Status}
			if v.Expires > 0 {
				entry["expires"] = v.Expires
			}
			if strings.EqualFold(v.Status, "expired") {
				expired++
			}
			out[k] = entry
		}
		facts["licenses"] = out
		metrics["licenses_expired"] = float64(expired)
	} else {
		optional("licenses", err)
	}

	// administrative settings (read-only CMDB)
	var gl struct {
		Results struct {
			AdminSport   int    `json:"admin-sport"`
			AdminSSHPort int    `json:"admin-ssh-port"`
			AdminTimeout int    `json:"admintimeout"`
			Timezone     string `json:"timezone"`
		} `json:"results"`
	}
	if err := get("/api/v2/cmdb/system/global", &gl); err == nil {
		facts["admin_https_port"] = gl.Results.AdminSport
		facts["admin_ssh_port"] = gl.Results.AdminSSHPort
		facts["admin_timeout_min"] = gl.Results.AdminTimeout
		facts["timezone"] = gl.Results.Timezone
	} else {
		optional("system global", err)
	}

	// the logs: who fails at the admin login, who fails at the VPN, what the IPS saw
	// (ADR-0018 §7). Memory logs are on by default on every model; disk when it has one.
	source := "memory"
	if st.Results.LogDiskStatus == "available" {
		source = "disk"
	}
	now := t.Now
	if now.IsZero() {
		now = time.Now()
	}
	for _, lg := range fortigateLogs {
		var page struct {
			Results []map[string]any `json:"results"`
		}
		// the path of a log differs between releases; the one that answered is remembered
		paths := lg.paths
		if p := t.State["log_path:"+lg.kind]; p != "" {
			paths = append([]string{p}, paths...)
		}
		var err error
		found := false
		for _, path := range paths {
			if err = get("/api/v2/log/"+source+"/"+path+"?rows=300", &page); err == nil {
				t.State["log_path:"+lg.kind] = path
				found = true
				break
			}
			if !strings.Contains(err.Error(), "HTTP 404") {
				break
			}
		}
		if !found {
			optional("log "+lg.kind, err)
			continue
		}
		reading.Signals = append(reading.Signals, fortigateLogSignals(lg.kind, page.Results, t.State, now)...)
	}
	if len(problems) > 0 {
		facts["problems"] = problems
	}
	reading.Facts, reading.Metrics = facts, metrics
	return reading, nil
}

// fortigateLogs names the logs read and the REST paths they may have; the first
// that answers wins and is remembered per connector.
var fortigateLogs = []struct {
	kind  string
	paths []string
}{
	{"event/system", []string{"event/system"}},
	{"event/vpn", []string{"event/vpn"}},
	{"ips", []string{"ips/signature", "utm/ips", "ips"}},
}

// logLookback bounds the first read of a log: without a cursor (agent start),
// only rows this fresh count, so a restart never replays the past.
const logLookback = 10 * time.Minute

// fortigateLogSignals turns log rows into signals, one per source and kind (and
// per signature for the IPS), counting only rows newer than the cursor of the
// last read. FortiOS stamps rows with eventtime in nanoseconds; the cursor is
// that number.
func fortigateLogSignals(kind string, rows []map[string]any, state map[string]string, now time.Time) []wire.Signal {
	cursorKey := "log_cursor:" + kind
	cursor, _ := strconv.ParseInt(state[cursorKey], 10, 64)
	if cursor == 0 {
		cursor = now.Add(-logLookback).UnixNano()
	}
	newest := cursor
	type agg struct {
		sig   wire.Signal
		users map[string]bool
	}
	byKey := map[string]*agg{}
	var order []string
	for _, row := range rows {
		et, ok := number(row["eventtime"])
		if !ok || et <= cursor {
			continue
		}
		if et > newest {
			newest = et
		}
		var sig wire.Signal
		src := str(row["srcip"])
		switch kind {
		case "event/system":
			if str(row["action"]) != "login" || str(row["status"]) != "failed" {
				continue
			}
			sig = wire.Signal{Kind: wire.SignalFGTAdminFail, IP: src, Count: 1}
		case "event/vpn":
			if a := str(row["action"]); a != "ssl-login-fail" && !(strings.Contains(str(row["logdesc"]), "login fail")) {
				continue
			}
			sig = wire.Signal{Kind: wire.SignalFGTVPNFail, IP: src, Count: 1}
		case "ips":
			attack := str(row["attack"])
			if attack == "" {
				continue
			}
			sig = wire.Signal{Kind: wire.SignalFGTIPS, IP: src, Count: 1, Detail: attack + "|" + str(row["severity"]) + "|" + str(row["action"])}
		default:
			continue
		}
		key := sig.Kind + "|" + sig.IP + "|" + sig.Detail
		a, ok := byKey[key]
		if !ok {
			at := time.Unix(0, et).UTC()
			sig.FirstAt, sig.LastAt = at, at
			a = &agg{sig: sig, users: map[string]bool{}}
			byKey[key] = a
			order = append(order, key)
		} else {
			a.sig.Count++
			at := time.Unix(0, et).UTC()
			if at.After(a.sig.LastAt) {
				a.sig.LastAt = at
			}
			if at.Before(a.sig.FirstAt) {
				a.sig.FirstAt = at
			}
		}
		if u := str(row["user"]); u != "" && kind != "ips" {
			a.users[u] = true
		}
	}
	state[cursorKey] = strconv.FormatInt(newest, 10)
	out := make([]wire.Signal, 0, len(order))
	for _, key := range order {
		a := byKey[key]
		if len(a.users) > 0 {
			users := make([]string, 0, len(a.users))
			for u := range a.users {
				users = append(users, u)
			}
			sort.Strings(users)
			if len(users) > 5 {
				users = append(users[:5], "…")
			}
			a.sig.Detail = strings.Join(users, ", ")
		}
		out = append(out, a.sig)
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// number reads a JSON number that FortiOS may send as a string (eventtime).
func number(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	}
	return 0, false
}
