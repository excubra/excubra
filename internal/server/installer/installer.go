// Package installer knows the one-liners that turn a machine or a Proxmox
// container into a box. The console prints them and so does the MCP server;
// they must be the same text, so they are built in one place.
package installer

import (
	"regexp"
	"strings"

	"github.com/excubra/excubra/internal/version"
)

// Command is one way to bring a box to life, with a title a person reads.
type Command struct {
	Title string `json:"title"`
	Cmd   string `json:"cmd"`
}

var releaseRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// Base is where the installers of this server's release live; a development
// build points at main. ver is empty for a development build.
func Base() (base, ver string) {
	ref := "main"
	if v := version.Version; releaseRe.MatchString(v) {
		ref, ver = "v"+v, v
	}
	return "https://raw.githubusercontent.com/excubra/excubra/" + ref + "/image", ver
}

// Reinstall brings an enrolled box's installation up to the current release
// (units, helper, firewall rules) without touching its identity: the installer
// without a key, run once on the box.
func Reinstall() string {
	base, ver := Base()
	cmd := "curl -fsSL " + base + "/ex0-box.sh | bash -s --"
	if ver != "" {
		cmd += " --version " + ver
	}
	return cmd
}

// Commands are the two ways a box comes to life with this key: on a machine
// (mini PC, Pi, VM) and as a container on a Proxmox host.
func Commands(key, hostname string) []Command {
	base, ver := Base()
	args := "--enroll-key '" + key + "'"
	if hostname != "" {
		args += " --hostname " + hostname
	}
	if ver != "" {
		args += " --version " + ver
	}
	return []Command{
		{Title: "Auf einem Proxmox-Host (legt den Container an und richtet ihn ein)", Cmd: "curl -fsSL " + base + "/ex0-box-pct.sh | bash -s -- " + args},
		{Title: "Auf der Box selbst (Mini-PC, Raspberry Pi, VM mit frischem Debian, als root)", Cmd: "curl -fsSL " + base + "/ex0-box.sh | bash -s -- " + args},
	}
}

// Hostname makes a hostname out of tenant and site: letters, digits, dashes.
func Hostname(tenant, site string) string {
	slug := func(v string) string {
		v = strings.ToLower(strings.TrimSpace(v))
		r := strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss")
		v = r.Replace(v)
		var b strings.Builder
		dash := false
		for _, c := range v {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
				b.WriteRune(c)
				dash = false
			default:
				if !dash && b.Len() > 0 {
					b.WriteByte('-')
					dash = true
				}
			}
		}
		return strings.Trim(b.String(), "-")
	}
	name := strings.Trim(slug(tenant)+"-"+slug(site), "-")
	if len(name) > 40 {
		name = strings.Trim(name[:40], "-")
	}
	if name == "" {
		return "ex0-box"
	}
	return "ex0-" + name
}
