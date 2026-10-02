// Package installer knows the one-liners that turn a machine or a Proxmox
// container into a box. The console prints them and so does the MCP server;
// they must be the same text, so they are built in one place.
package installer

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/excubra/excubra/internal/version"
)

// Command is one way to bring a box to life, with a title a person reads.
type Command struct {
	Title string `json:"title"`
	Cmd   string `json:"cmd"`
}

// Options is what a rollout knows before the box exists: where on the
// hypervisor the container goes, and who may log in afterwards. Every field is
// optional — the installer has a default for each — but a value that is known
// belongs into the command, not into a sentence next to it: on 29.09.2026 the
// values were handed over beside the command, the command was run without
// them, and the box landed on the next free id with an address from DHCP.
type Options struct {
	CTID    int    // Proxmox container id; 0 = the next free one
	Bridge  string // the LAN's bridge; "" = vmbr0, else the default route's
	IP      string // "dhcp" (or "") or address/prefix, e.g. 192.168.10.60/24
	GW      string // gateway, with a fixed address
	Storage string // storage for the container's disk; "" = local-lvm, local-zfs, else the first that takes one
	Disk    int    // GiB; 0 = 8
	Memory  int    // MiB; 0 = 1024
	// SSHKeys are the technicians' public keys for root on the box. Without
	// one nobody can log in: sshd takes keys only. They travel in the command a
	// person runs on the box and are never something the server hands a box
	// later (ADR-0024).
	SSHKeys []string
}

var (
	releaseRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,62}$`)
	// one line: type, base64, an optional name without anything a shell cares about
	sshKeyRe = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]{40,}( [A-Za-z0-9@._:+-]{1,80})?$`)
)

// Validate refuses what would not survive the shell or the installer. The
// values end up in a command a person pastes as root, so the rule is a closed
// alphabet per field rather than quoting cleverly.
func (o Options) Validate() error {
	if o.CTID != 0 && (o.CTID < 100 || o.CTID > 999999999) {
		return errors.New("ctid: 100 und höher")
	}
	if o.Bridge != "" && (!nameRe.MatchString(o.Bridge) || len(o.Bridge) > 15) {
		return errors.New("bridge: der Name der Bridge, z. B. vmbr0")
	}
	if o.Storage != "" && !nameRe.MatchString(o.Storage) {
		return errors.New("storage: der Name des Speichers, z. B. local-lvm")
	}
	if o.Disk != 0 && (o.Disk < 4 || o.Disk > 500) {
		return errors.New("disk: 4 bis 500 GiB")
	}
	if o.Memory != 0 && (o.Memory < 512 || o.Memory > 65536) {
		return errors.New("memory: 512 bis 65536 MiB")
	}
	switch o.IP {
	case "", "dhcp":
		if o.GW != "" {
			return errors.New("gw: nur mit fester Adresse (ip)")
		}
	default:
		p, err := netip.ParsePrefix(o.IP)
		if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 30 {
			return errors.New("ip: dhcp oder Adresse mit Präfixlänge, z. B. 192.168.10.60/24")
		}
		if p.Addr() == p.Masked().Addr() {
			return errors.New("ip: das ist die Netzadresse, nicht die Adresse der Box")
		}
		gw, err := netip.ParseAddr(o.GW)
		if err != nil || !gw.Is4() {
			return errors.New("gw: eine feste Adresse braucht das Gateway dieses Netzes")
		}
		if !p.Contains(gw) {
			return fmt.Errorf("gw: %s liegt nicht im Netz %s", gw, p.Masked())
		}
		if gw == p.Addr() {
			return errors.New("gw: Box und Gateway haben dieselbe Adresse")
		}
	}
	if len(o.SSHKeys) > 10 {
		return errors.New("ssh_keys: höchstens zehn")
	}
	for _, k := range o.SSHKeys {
		if !sshKeyRe.MatchString(k) {
			return errors.New("ssh_keys: ein öffentlicher Schlüssel je Eintrag (Typ, Schlüssel, optional ein Name ohne Leerzeichen) — keine Optionen, kein privater Schlüssel")
		}
	}
	return nil
}

// Base is where the installers of this server's release live; a development
// build points at main. ver is empty for a development build.
func Base() (base, ver string) {
	ref := "main"
	if v := version.Version; releaseRe.MatchString(v) {
		ref, ver = "v"+v, v
	}
	return "https://raw.githubusercontent.com/excubra/excubra/" + ref + "/image", ver
}

// run is the shape of every command: load the script into a file, then run the
// file. Piped straight into a shell, a download that fails is an empty script
// that ends quietly, and one that breaks off half-way is half a script that runs.
func run(script, args string) string {
	base, _ := Base()
	cmd := "curl -fsSL " + base + "/" + script + " -o /tmp/" + script + " && bash /tmp/" + script
	if args != "" {
		cmd += " " + args
	}
	return cmd
}

// Reinstall brings an enrolled box's installation up to the current release
// (units, helper, firewall rules) without touching its identity: the installer
// without a key, run once on the box.
func Reinstall() string {
	_, ver := Base()
	args := ""
	if ver != "" {
		args = "--version " + ver
	}
	return run("ex0-box.sh", args)
}

// Commands are the two ways a box comes to life with this key: as a container
// on a Proxmox host and on a machine of its own (mini PC, Pi). o must have
// passed Validate; the container values go into the first command only.
func Commands(key, hostname string, o Options) []Command {
	_, ver := Base()
	args := "--enroll-key '" + key + "'"
	if hostname != "" {
		args += " --hostname " + hostname
	}
	if ver != "" {
		args += " --version " + ver
	}
	ssh := ""
	for _, k := range o.SSHKeys {
		ssh += " --ssh-key '" + k + "'"
	}
	pct := ""
	if o.CTID != 0 {
		pct += " --ctid " + strconv.Itoa(o.CTID)
	}
	if o.Bridge != "" {
		pct += " --bridge " + o.Bridge
	}
	if o.IP != "" && o.IP != "dhcp" {
		pct += " --ip " + o.IP + " --gw " + o.GW
	}
	if o.Storage != "" {
		pct += " --storage " + o.Storage
	}
	if o.Disk != 0 {
		pct += " --disk " + strconv.Itoa(o.Disk)
	}
	if o.Memory != 0 {
		pct += " --memory " + strconv.Itoa(o.Memory)
	}
	return []Command{
		{Title: "Auf einem Proxmox-Host (legt den Container an und richtet ihn ein)", Cmd: run("ex0-box-pct.sh", args+pct+ssh)},
		{Title: "Auf der Box selbst (Mini-PC oder Raspberry Pi mit frischem Debian, als root — nie auf einem Host, der etwas anderes tut)", Cmd: run("ex0-box.sh", args+ssh)},
	}
}

// Hostname is what the box calls itself: ex0-<customer>-<site>, from the slugs
// the two identifiers were made of (ten_muster, site_kanzlei → ex0-muster-kanzlei).
// The display names are for people; a hostname made of them was fifty
// characters of somebody's legal form.
func Hostname(tenantID, siteID string) string {
	name := strings.Trim(slug(strings.TrimPrefix(tenantID, "ten_"))+"-"+slug(strings.TrimPrefix(siteID, "site_")), "-")
	if name == "" {
		return "ex0-box"
	}
	name = "ex0-" + name
	if len(name) > 63 {
		name = strings.Trim(name[:63], "-")
	}
	return name
}

// slug keeps letters, digits and single dashes.
func slug(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
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
