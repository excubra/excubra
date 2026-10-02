package installer

import (
	"strings"
	"testing"
)

func TestHostnameIsMadeOfTheSlugs(t *testing.T) {
	for _, c := range []struct{ tenant, site, want string }{
		{"ten_muster", "site_kanzlei", "ex0-muster-kanzlei"},
		{"ten_muster-gmbh", "site_werk-2", "ex0-muster-gmbh-werk-2"},
		{"", "", "ex0-box"},
		{"ten_" + strings.Repeat("a", 40), "site_" + strings.Repeat("b", 40), "ex0-" + strings.Repeat("a", 40) + "-" + strings.Repeat("b", 18)},
	} {
		got := Hostname(c.tenant, c.site)
		if got != c.want || len(got) > 63 {
			t.Errorf("Hostname(%q, %q) = %q, want %q", c.tenant, c.site, got, c.want)
		}
	}
}

// The values end up in a command a person pastes as root: a closed alphabet
// per field, and the combinations that cannot work are refused before a key
// is made for them.
func TestOptionsValidate(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlvZi4wdGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleQ"
	good := []Options{
		{},
		{IP: "dhcp"},
		{CTID: 200, Bridge: "vmbr0", IP: "192.168.10.60/24", GW: "192.168.10.1", Storage: "local-lvm", Disk: 8, Memory: 1024},
		{IP: "192.0.2.60/24", GW: "192.0.2.111"}, // a LAN outside RFC 1918 is still somebody's LAN
		{SSHKeys: []string{key, key + " jeremia@mac", "ssh-rsa " + strings.Repeat("A", 372) + " techniker-2"}},
	}
	for _, o := range good {
		if err := o.Validate(); err != nil {
			t.Errorf("%+v: %v", o, err)
		}
	}
	bad := []Options{
		{CTID: 99},
		{Bridge: "vmbr0;reboot"},
		{Bridge: "eine-viel-zu-lange-bridge"},
		{Storage: "local lvm"},
		{Storage: "`id`"},
		{Disk: 1}, {Memory: 64},
		{GW: "192.168.10.1"},                          // a gateway without an address
		{IP: "192.168.10.60"},                         // no prefix length
		{IP: "192.168.10.60/24"},                      // no gateway
		{IP: "192.168.10.60/24", GW: "192.168.11.1"},  // the gateway of another network
		{IP: "192.168.10.60/24", GW: "192.168.10.60"}, // the box as its own gateway
		{IP: "192.168.10.0/24", GW: "192.168.10.1"},   // the network address
		{IP: "192.168.10.60/31", GW: "192.168.10.61"},
		{IP: "fd00::60/64", GW: "fd00::1"},
		{SSHKeys: []string{"ssh-ed25519"}},
		{SSHKeys: []string{key + " zwei worte"}},
		{SSHKeys: []string{key + " o'brien"}},
		{SSHKeys: []string{"command=\"id\" " + key}},
		{SSHKeys: []string{key + "\n" + key}},
		{SSHKeys: make([]string, 11)},
	}
	for _, o := range bad {
		if err := o.Validate(); err == nil {
			t.Errorf("must be refused: %+v", o)
		}
	}
}

func TestCommandsLoadThenRun(t *testing.T) {
	o := Options{CTID: 200, IP: "192.168.10.60/24", GW: "192.168.10.1", SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlvZi4wdGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleQ t@x"}}
	cmds := Commands("EX0:1:ingest.example.test:443:abc:def", "ex0-muster-werk", o)
	if len(cmds) != 2 {
		t.Fatalf("two ways a box comes to life: %d", len(cmds))
	}
	for i, script := range []string{"ex0-box-pct.sh", "ex0-box.sh"} {
		c := cmds[i].Cmd
		if !strings.HasPrefix(c, "curl -fsSL https://raw.githubusercontent.com/excubra/excubra/") || !strings.Contains(c, "/image/"+script+" -o /tmp/"+script+" && bash /tmp/"+script+" --enroll-key 'EX0:1:") {
			t.Errorf("%s: %s", script, c)
		}
		if strings.Contains(c, "|") {
			t.Errorf("no pipe into a shell: %s", c)
		}
	}
	if !strings.Contains(cmds[0].Cmd, "--ctid 200 --ip 192.168.10.60/24 --gw 192.168.10.1 --ssh-key '") {
		t.Errorf("proxmox: %s", cmds[0].Cmd)
	}
	if strings.Contains(cmds[1].Cmd, "--ctid") || strings.Contains(cmds[1].Cmd, "--gw") {
		t.Errorf("a machine has no container values: %s", cmds[1].Cmd)
	}
	if r := Reinstall(); strings.Contains(r, "|") || !strings.Contains(r, "-o /tmp/ex0-box.sh && bash /tmp/ex0-box.sh") {
		t.Errorf("reinstall: %s", r)
	}
}
