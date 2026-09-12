package server

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/auth"
	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/seal"
	"github.com/excubra/excubra/internal/secretbox"
	"github.com/excubra/excubra/internal/server/ai"
	"github.com/excubra/excubra/internal/server/api"
	"github.com/excubra/excubra/internal/server/catalog"
	"github.com/excubra/excubra/internal/server/mcp"
	"github.com/excubra/excubra/internal/server/remote"
	"github.com/excubra/excubra/internal/server/selfupdate"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

// cliArgs separates positional words from flags, so both
// `tenant list --env-file X` and `tenant --env-file X list` work. Every flag in this
// CLI takes a value, so a bare "-x" consumes the next argument; "-x=y" does not.
func cliArgs(args []string) (positional, flags []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-":
			positional = append(positional, a) // "read the value from stdin", never a flag
		case a == "--":
			return append(positional, args[i+1:]...), flags
		case strings.HasPrefix(a, "-") && strings.Contains(a, "="):
			flags = append(flags, a)
		case strings.HasPrefix(a, "-"):
			flags = append(flags, a)
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		default:
			positional = append(positional, a)
		}
	}
	return positional, flags
}

// cliStore opens the store from the configuration for one-shot commands. The
// running server may keep the files open; SQLite in WAL mode allows both.
func cliStore(envFile string) (*store.Store, Config, error) {
	cfg, err := LoadConfig(envFile, os.Getenv)
	if err != nil {
		return nil, Config{}, err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return nil, cfg, err
	}
	if st.Secrets, err = loadSecrets(cfg); err != nil {
		_ = st.Close()
		return nil, cfg, err
	}
	return st, cfg, nil
}

// loadSecrets reads the key that seals secrets at rest, or nil when none is configured.
func loadSecrets(cfg Config) (*secretbox.Box, error) {
	if cfg.SecretKeyFile == "" {
		return nil, nil //nolint:nilnil // no key configured is a state, not an error
	}
	return secretbox.Load(cfg.SecretKeyFile)
}

// userCmd: excubra server user add|passwd|disable|enable|list
func userCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server user", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("usage: excubra server user add <name> | passwd <name> | disable <name> | enable <name> | list")
	}
	st, _, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	now := time.Now()
	switch rest[0] {
	case "add":
		if len(rest) != 2 {
			return fmt.Errorf("usage: excubra server user add <name>")
		}
		pw := auth.RandomPassword()
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		secret := auth.NewTOTPSecret()
		u := store.User{ID: id.New("usr"), Name: rest[1], PasswordHash: hash, TOTPSecret: secret, CreatedAt: now}
		if err := st.CreateUser(ctx, u); err != nil {
			return err
		}
		_ = st.Audit(ctx, now, "cli", "user.add", u.ID, u.Name)
		fmt.Printf("user %s created\n\ninitial password (shown once): %s\nTOTP secret:                  %s\nTOTP URI:                     %s\n", u.Name, pw, secret, auth.TOTPURI("EX0", u.Name, secret))
		return nil
	case "passwd":
		if len(rest) != 2 {
			return fmt.Errorf("usage: excubra server user passwd <name>")
		}
		u, err := st.UserByName(ctx, rest[1])
		if err != nil {
			return err
		}
		pw := auth.RandomPassword()
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		if err := st.SetUserPassword(ctx, u.ID, hash); err != nil {
			return err
		}
		if err := st.UpdateUserLoginState(ctx, u.ID, 0, nil, u.TOTPLastCounter); err != nil {
			return err
		}
		_ = st.Audit(ctx, now, "cli", "user.passwd", u.ID, u.Name)
		fmt.Printf("new password for %s (shown once): %s\n", u.Name, pw)
		return nil
	case "disable", "enable":
		if len(rest) != 2 {
			return fmt.Errorf("usage: excubra server user %s <name>", rest[0])
		}
		u, err := st.UserByName(ctx, rest[1])
		if err != nil {
			return err
		}
		if err := st.SetUserDisabled(ctx, u.ID, rest[0] == "disable"); err != nil {
			return err
		}
		_ = st.Audit(ctx, now, "cli", "user."+rest[0], u.ID, u.Name)
		fmt.Printf("user %s %sd\n", u.Name, rest[0])
		return nil
	case "list":
		users, err := st.Users(ctx)
		if err != nil {
			return err
		}
		for _, u := range users {
			status := "active"
			if u.Disabled {
				status = "disabled"
			}
			fmt.Printf("%-24s %-8s created %s\n", u.Name, status, u.CreatedAt.Format(time.RFC3339))
		}
		return nil
	}
	return fmt.Errorf("user: unknown subcommand %q", rest[0])
}

// keyCmd: excubra server key new [--count N] [--note text] [--expires-days D]
func keyCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server key", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	count := fs.Int("count", 1, "how many keys to create")
	note := fs.String("note", "", "note stored with the keys (e.g. batch name)")
	site := fs.String("site", "", "the site the box lands at on enrollment (ADR-0017)")
	days := fs.Int("expires-days", 30, "validity in days")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 || rest[0] != "new" {
		return fmt.Errorf("usage: excubra server key new [--count N] [--note text] [--expires-days D] [--site <site_id>]")
	}
	if *count < 1 || *count > 500 {
		return fmt.Errorf("count must be 1..500")
	}
	st, cfg, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ca, err := pki.LoadOrCreateCA(filepath.Join(cfg.DataDir, "ca"))
	if err != nil {
		return err
	}
	host, portStr := cfg.IngestHostPort()
	port, _ := strconv.Atoi(portStr)
	ctx := context.Background()
	now := time.Now()
	for i := 0; i < *count; i++ {
		k, err := pki.NewEnrollmentKey(host, port, ca.Fingerprint())
		if err != nil {
			return err
		}
		rec := store.EnrollmentKey{ID: id.New("key"), SecretHash: k.SecretHash(), Note: *note, SiteID: *site, CreatedAt: now, ExpiresAt: now.Add(time.Duration(*days) * 24 * time.Hour)}
		if err := st.CreateEnrollmentKey(ctx, rec); err != nil {
			return err
		}
		_ = st.Audit(ctx, now, "cli", "key.new", rec.ID, *note)
		fmt.Printf("%s\t%s\n", rec.ID, k.String())
	}
	return nil
}

// tokenCmd: excubra server token new --name X [--tenants a,b] | list | revoke <id>
func tokenCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server token", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	name := fs.String("name", "", "token name (e.g. crm)")
	tenants := fs.String("tenants", "*", "comma-separated tenant ids or * for all")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("usage: excubra server token new --name X [--tenants a,b] | list | revoke <id>")
	}
	st, _, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	now := time.Now()
	switch rest[0] {
	case "new":
		if *name == "" {
			return fmt.Errorf("--name is required")
		}
		raw := "ex0_" + id.Secret(32)
		t := store.APIToken{ID: id.New("tok"), Name: *name, TokenHash: api.HashToken(raw), Tenants: strings.Split(*tenants, ","), CreatedAt: now}
		if err := st.CreateAPIToken(ctx, t); err != nil {
			return err
		}
		_ = st.Audit(ctx, now, "cli", "token.new", t.ID, *name)
		fmt.Printf("token %s (%s) created — shown once:\n%s\n", t.ID, t.Name, raw)
		return nil
	case "list":
		toks, err := st.APITokens(ctx)
		if err != nil {
			return err
		}
		for _, t := range toks {
			state := "active"
			if t.RevokedAt != nil {
				state = "revoked"
			}
			fmt.Printf("%s\t%-20s %-8s tenants=%s\n", t.ID, t.Name, state, strings.Join(t.Tenants, ","))
		}
		return nil
	case "revoke":
		if len(rest) != 2 {
			return fmt.Errorf("usage: excubra server token revoke <id>")
		}
		if err := st.RevokeAPIToken(ctx, rest[1], now); err != nil {
			return err
		}
		_ = st.Audit(ctx, now, "cli", "token.revoke", rest[1], "")
		fmt.Println("revoked")
		return nil
	}
	return fmt.Errorf("token: unknown subcommand %q", rest[0])
}

// tenantCmd: excubra server tenant add <slug> <name> | list
// siteCmd:   excubra server site add <tenant_id> <slug> <name> | list
func tenantCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server tenant", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	st, _, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	switch {
	case len(rest) == 3 && rest[0] == "add":
		tid, err := id.FromSlug("ten", rest[1])
		if err != nil {
			return err
		}
		if err := st.CreateTenant(ctx, store.Tenant{ID: tid, Name: rest[2], CreatedAt: time.Now()}); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "tenant.add", tid, rest[2])
		fmt.Println(tid)
		return nil
	case len(rest) == 3 && rest[0] == "ai" && (rest[2] == store.AIScopeOff || rest[2] == store.AIScopeFacts):
		// what the AI may see for this tenant (ADR-0019)
		if _, err := st.Tenant(ctx, rest[1]); err != nil {
			return err
		}
		if err := st.SetTenantAI(ctx, rest[1], rest[2]); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "tenant.ai", rest[1], rest[2])
		fmt.Printf("ai scope of %s: %s\n", rest[1], rest[2])
		return nil
	case len(rest) == 1 && rest[0] == "list":
		ts, err := st.Tenants(ctx)
		if err != nil {
			return err
		}
		for _, t := range ts {
			fmt.Printf("%s\t%s\n", t.ID, t.Name)
		}
		return nil
	}
	return fmt.Errorf("usage: excubra server tenant add <slug> <name> | list | ai <tenant_id> off|facts")
}

func siteCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server site", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	st, _, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	switch {
	case len(rest) == 4 && rest[0] == "add":
		if _, err := st.Tenant(ctx, rest[1]); err != nil {
			return err
		}
		sid, err := id.FromSlug("site", rest[2])
		if err != nil {
			return err
		}
		if err := st.CreateSite(ctx, store.Site{ID: sid, TenantID: rest[1], Name: rest[3], CreatedAt: time.Now()}); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "site.add", sid, rest[3])
		fmt.Println(sid)
		return nil
	case len(rest) == 1 && rest[0] == "list":
		ss, err := st.Sites(ctx, "")
		if err != nil {
			return err
		}
		for _, s := range ss {
			scan, canary, dns := "scan=off", "canary=off", "dns=off"
			if s.ScanEnabled {
				scan = "scan=on"
			}
			if s.CanaryEnabled {
				canary = "canary=on"
			}
			switch {
			case s.DNSEnabled && s.DNSBlock:
				dns = "dns=block"
			case s.DNSEnabled:
				dns = "dns=report"
			}
			fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n", s.ID, s.TenantID, s.Name, scan, canary, dns)
		}
		return nil
	case len(rest) == 3 && rest[0] == "scan" && (rest[2] == "on" || rest[2] == "off"):
		// the service scan switch (ADR-0018); the running server reads it fresh for every config
		if _, err := st.Site(ctx, rest[1]); err != nil {
			return err
		}
		if err := st.SetSiteScan(ctx, rest[1], rest[2] == "on"); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "site.scan", rest[1], rest[2])
		fmt.Printf("scan %s for %s; the box picks it up with its next config pull\n", rest[2], rest[1])
		return nil
	case len(rest) == 3 && rest[0] == "dns" && (rest[2] == "on" || rest[2] == "off" || rest[2] == "block" || rest[2] == "report"):
		// the DNS sensor (ADR-0020): on = reporting, block = reporting and blocking
		site, err := st.Site(ctx, rest[1])
		if err != nil {
			return err
		}
		enabled, block := rest[2] != "off", rest[2] == "block"
		if rest[2] == "report" {
			enabled, block = true, false
		}
		if err := st.SetSiteDNS(ctx, rest[1], enabled, block, site.DNSUpstreams); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "site.dns", rest[1], rest[2])
		fmt.Printf("dns %s for %s; the box picks it up with its next config pull\n", rest[2], rest[1])
		return nil
	case len(rest) == 3 && rest[0] == "canary" && (rest[2] == "on" || rest[2] == "off"):
		// the live detection switch (ADR-0018 §7): decoy ports and signals
		if _, err := st.Site(ctx, rest[1]); err != nil {
			return err
		}
		if err := st.SetSiteCanary(ctx, rest[1], rest[2] == "on"); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "site.canary", rest[1], rest[2])
		fmt.Printf("canary %s for %s; the box picks it up with its next config pull\n", rest[2], rest[1])
		return nil
	}
	return fmt.Errorf("usage: excubra server site add <tenant_id> <slug> <name> | list | scan <site_id> on|off | canary <site_id> on|off | dns <site_id> on|off|block|report")
}

// boxCmd: excubra server box list | assign <box_id> <site_id> | unassign <box_id>
//
// assign writes the box→site binding to the store. The running server rebuilds its
// in-memory state from the store only at startup (core.Load), so it must be restarted
// after an assign for the change to take effect — assign prints that reminder.
func boxCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server box", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	st, _, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	switch {
	case len(rest) == 1 && rest[0] == "list":
		boxes, err := st.Boxes(ctx, "")
		if err != nil {
			return err
		}
		if len(boxes) == 0 {
			fmt.Println("(no boxes enrolled)")
			return nil
		}
		for _, b := range boxes {
			site := b.SiteID
			if site == "" {
				site = "-unassigned-"
			}
			seen := "never"
			if !b.LastSeen.IsZero() {
				seen = b.LastSeen.UTC().Format("2006-01-02T15:04:05Z")
			}
			ver := b.AgentVersion
			if ver == "" {
				ver = "-"
			}
			plat := strings.TrimSuffix(b.OS+"/"+b.Arch, "/")
			sealFP := "-"
			if fp := seal.Fingerprint(b.SealKey); fp != "" {
				sealFP = strings.ReplaceAll(fp, " ", "")
			}
			fmt.Printf("%s\tsite=%s\tv=%s\t%s\tseen=%s\tnb=%s\tseal=%s\n", b.ID, site, ver, plat, seen, b.NetbirdStatus, sealFP)
		}
		return nil
	case len(rest) == 3 && rest[0] == "assign":
		if _, err := st.Box(ctx, rest[1]); err != nil {
			return fmt.Errorf("box %s: %w", rest[1], err)
		}
		site, err := st.Site(ctx, rest[2])
		if err != nil {
			return fmt.Errorf("site %s: %w", rest[2], err)
		}
		if err := st.AssignBox(ctx, rest[1], site.ID); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "box.assign", rest[1], site.ID)
		fmt.Printf("%s assigned to %s (%s)\n", rest[1], site.ID, site.Name)
		fmt.Println("restart the server to apply: systemctl restart excubra-server")
		return nil
	case len(rest) == 2 && rest[0] == "unassign":
		if _, err := st.Box(ctx, rest[1]); err != nil {
			return fmt.Errorf("box %s: %w", rest[1], err)
		}
		if err := st.AssignBox(ctx, rest[1], ""); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "box.assign", rest[1], "")
		fmt.Printf("%s unassigned\n", rest[1])
		fmt.Println("restart the server to apply: systemctl restart excubra-server")
		return nil
	case len(rest) == 3 && rest[0] == "role" && (rest[2] == store.RoleBox || rest[2] == store.RoleOutpost):
		// an outpost scans the sites' public addresses from our infrastructure (ADR-0018)
		if _, err := st.Box(ctx, rest[1]); err != nil {
			return err
		}
		if err := st.SetBoxRole(ctx, rest[1], rest[2]); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "box.role", rest[1], rest[2])
		fmt.Printf("%s is now a %s; it picks its new config up with the next pull\n", rest[1], rest[2])
		return nil
	case len(rest) == 3 && rest[0] == "task":
		// the same closed list the console offers (ADR-0014), for an operator on the server
		kind := rest[2]
		if !wire.ValidTaskKind(kind) {
			return fmt.Errorf("task kind must be one of %s", strings.Join(wire.TaskKinds, ", "))
		}
		box, err := st.Box(ctx, rest[1])
		if err != nil {
			return fmt.Errorf("box %s: %w", rest[1], err)
		}
		if box.RevokedAt != nil {
			return fmt.Errorf("box %s is revoked", box.ID)
		}
		now := time.Now()
		pending, err := st.PendingBoxTasks(ctx, box.ID, now)
		if err != nil {
			return err
		}
		for _, t := range pending {
			if t.Kind == kind {
				fmt.Printf("%s already waits for the box since %s\n", kind, t.IssuedAt.UTC().Format(time.RFC3339))
				return nil
			}
		}
		t := store.BoxTask{ID: id.New("task"), BoxID: box.ID, Kind: kind, IssuedAt: now, IssuedBy: "cli", ExpiresAt: now.Add(time.Hour)}
		if err := st.CreateBoxTask(ctx, t); err != nil {
			return err
		}
		_ = st.Audit(ctx, now, "cli", "box.task", box.ID, kind+" "+t.ID)
		fmt.Printf("%s queued for %s (%s); the box picks it up with its next config pull\n", kind, box.ID, t.ID)
		return nil
	}
	return fmt.Errorf("usage: excubra server box list | assign <box_id> <site_id> | unassign <box_id> | task <box_id> <sweep|recheck|update|restart> | role <box_id> box|outpost")
}

// backupCmd: excubra server backup <dir>
func backupCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server backup", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: excubra server backup <dir>")
	}
	st, _, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if err := st.Backup(context.Background(), rest[0], time.Now()); err != nil {
		return err
	}
	fmt.Println("backup written to", rest[0])
	return nil
}

// pruneCmd: excubra server prune --keep <days>
func pruneCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server prune", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	keep := fs.Int("keep", 90, "days of day files to keep")
	_, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if *keep < 1 {
		return fmt.Errorf("--keep must be at least 1 day")
	}
	st, _, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	removed, err := st.Prune(time.Duration(*keep)*24*time.Hour, time.Now())
	if err != nil {
		return err
	}
	for _, p := range removed {
		fmt.Println("removed", p)
	}
	fmt.Printf("%d day file(s) removed\n", len(removed))
	return nil
}

// releaseCmd registers release metadata (ADR-0006) and points channels at versions:
//
//	excubra server release list
//	excubra server release add --version 0.2.0 --os linux --arch amd64 --url https://… --sha256 … --sig … [--min-agent 0.1.0]
//	excubra server release import --version 0.2.0 --dir dist/ --base-url https://github.com/excubra/excubra/releases/download/v0.2.0 [--min-agent 0.1.0]
//	excubra server release channel <stable|canary> <version|->
//
// import reads SHA256SUMS and excubra_linux_<arch>.sig from a release directory, which
// is exactly what the release workflow produces. The server never stores a binary.
func releaseCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server release", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	version := fs.String("version", "", "release version without the v")
	osName := fs.String("os", "linux", "operating system")
	arch := fs.String("arch", "", "amd64 or arm64")
	url := fs.String("url", "", "where the binary lies (add)")
	sha := fs.String("sha256", "", "hex sha256 of the binary (add)")
	sig := fs.String("sig", "", "base64 cosign signature over the binary (add)")
	minAgent := fs.String("min-agent", "", "oldest agent allowed to install this")
	dir := fs.String("dir", "", "release directory with SHA256SUMS and .sig files (import)")
	baseURL := fs.String("base-url", "", "URL prefix the binaries are published under (import)")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	st, cfg, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	v := strings.TrimPrefix(strings.TrimSpace(*version), "v")
	switch {
	case len(rest) == 1 && rest[0] == "list":
		rels, err := st.Releases(ctx)
		if err != nil {
			return err
		}
		for _, ch := range []string{"stable", "canary"} {
			cv, _ := st.ChannelVersion(ctx, ch)
			if cv == "" {
				cv = "-"
			}
			fmt.Printf("channel %s → %s\n", ch, cv)
		}
		if len(rels) == 0 {
			fmt.Println("(no releases stored)")
			return nil
		}
		for _, r := range rels {
			fmt.Printf("%s\t%s/%s\tmin=%s\t%s\n", r.Version, r.OS, r.Arch, orDash(r.MinAgentVersion), r.URL)
		}
		return nil
	case len(rest) == 1 && rest[0] == "sync":
		if cfg.ReleaseCatalog == "" || cfg.ReleaseCatalog == "off" {
			return fmt.Errorf("the release catalog is off (EXCUBRA_RELEASE_CATALOG)")
		}
		added, err := catalog.New(cfg.ReleaseCatalog, st, nil).Sync(ctx)
		if err != nil {
			return err
		}
		if len(added) == 0 {
			fmt.Println("catalog checked, nothing new")
		} else {
			fmt.Printf("catalog: added %s\n", strings.Join(added, ", "))
		}
		return nil
	case len(rest) == 1 && rest[0] == "add":
		if v == "" || *arch == "" || *url == "" || *sha == "" || *sig == "" {
			return fmt.Errorf("release add needs --version, --arch, --url, --sha256 and --sig")
		}
		r := store.Release{Version: v, OS: *osName, Arch: *arch, URL: *url, SHA256: strings.ToLower(*sha), Signature: *sig, MinAgentVersion: *minAgent, CreatedAt: time.Now()}
		if err := st.PutRelease(ctx, r); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "release.add", v, r.OS+"/"+r.Arch)
		fmt.Printf("release %s %s/%s stored\n", v, r.OS, r.Arch)
		return nil
	case len(rest) == 1 && rest[0] == "import":
		if v == "" || *dir == "" || *baseURL == "" {
			return fmt.Errorf("release import needs --version, --dir and --base-url")
		}
		sums, err := os.ReadFile(filepath.Join(*dir, "SHA256SUMS"))
		if err != nil {
			return err
		}
		n := 0
		for _, line := range strings.Split(string(sums), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || !strings.HasPrefix(fields[1], "excubra_linux_") {
				continue
			}
			name := strings.TrimPrefix(fields[1], "*")
			a := strings.TrimPrefix(name, "excubra_linux_")
			if a != "amd64" && a != "arm64" { // the checksum file names the path; only the two known names are read
				continue
			}
			sigB, err := os.ReadFile(filepath.Join(*dir, name+".sig")) //nolint:gosec // name is one of two constants after the check above
			if err != nil {
				return fmt.Errorf("%s: %w", name+".sig", err)
			}
			r := store.Release{Version: v, OS: "linux", Arch: a, URL: strings.TrimSuffix(*baseURL, "/") + "/" + name,
				SHA256: strings.ToLower(fields[0]), Signature: strings.TrimSpace(string(sigB)), MinAgentVersion: *minAgent, CreatedAt: time.Now()}
			if err := st.PutRelease(ctx, r); err != nil {
				return err
			}
			_ = st.Audit(ctx, time.Now(), "cli", "release.add", v, "linux/"+a)
			fmt.Printf("release %s linux/%s stored → %s\n", v, a, r.URL)
			n++
		}
		if n == 0 {
			return fmt.Errorf("no excubra_linux_* entries in %s", filepath.Join(*dir, "SHA256SUMS"))
		}
		return nil
	case len(rest) == 3 && rest[0] == "channel":
		ch, want := rest[1], strings.TrimPrefix(rest[2], "v")
		if ch != "stable" && ch != "canary" {
			return fmt.Errorf("channel must be stable or canary")
		}
		if want == "-" {
			want = ""
		}
		if want != "" {
			rels, err := st.Releases(ctx)
			if err != nil {
				return err
			}
			known := false
			for _, r := range rels {
				if r.Version == want {
					known = true
				}
			}
			if !known {
				return fmt.Errorf("version %s is not stored; release add or import it first", want)
			}
		}
		if err := st.SetChannelVersion(ctx, ch, want); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "release.channel", ch, want)
		fmt.Printf("channel %s → %s\n", ch, orDash(want))
		return nil
	}
	return fmt.Errorf("usage: excubra server release list | sync | add … | import … | channel <stable|canary> <version|->")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// selftestCmd is what the updater runs on a candidate binary before swapping it in
// (ADR-0006): the new build must start, read the configuration and see the data
// directory. It touches nothing.
func selftestCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server selftest", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*envFile, os.Getenv)
	if err != nil {
		return fmt.Errorf("selftest: %w", err)
	}
	if _, err := os.Stat(cfg.DataDir); err != nil {
		return fmt.Errorf("selftest: data dir: %w", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "main.db")); err != nil {
		return fmt.Errorf("selftest: %w", err)
	}
	fmt.Println("selftest ok:", version.String())
	return nil
}

// updateCmd: excubra server update now | status
func updateCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server update", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	st, cfg, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	c := selfupdate.New(st, nil, cfg.DataDir, runtime.GOOS, runtime.GOARCH, cfg.SelfUpdate == "on", nil)
	switch {
	case len(rest) == 1 && rest[0] == "status":
		s := c.Status(ctx)
		fmt.Printf("running=%s channel=%s target=%s available=%s enabled=%v\n", s.Running, s.Channel, orDash(s.Target), orDash(s.Available), s.Enabled)
		return nil
	case len(rest) == 1 && rest[0] == "now":
		if err := selfupdate.RequestNow(cfg.DataDir); err != nil {
			return err
		}
		s := c.Status(ctx)
		if s.Available == "" {
			fmt.Printf("check requested; nothing newer than %s on channel %s right now\n", s.Running, s.Channel)
		} else {
			fmt.Printf("check requested; the running server will install %s within a minute and restart\n", s.Available)
		}
		return nil
	case len(rest) == 2 && rest[0] == "channel":
		if err := c.SetChannel(ctx, rest[1]); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "server.channel", rest[1], "")
		fmt.Printf("server follows channel %s\n", rest[1])
		return nil
	}
	return fmt.Errorf("usage: excubra server update status | now | channel <stable|canary|off>")
}

// settingCmd: excubra server setting get <key> | set <key> <value|-> (- reads the
// value from stdin, so a token from a password manager never shows in a process
// list or a shell history).
func settingCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server setting", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	st, _, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	switch {
	case len(rest) == 2 && rest[0] == "get":
		v, err := st.Setting(ctx, rest[1])
		if err != nil {
			return err
		}
		if store.SecretSetting(rest[1]) || strings.Contains(rest[1], "token") || strings.Contains(rest[1], "secret") {
			if v == "" {
				fmt.Println("(unset)")
			} else {
				fmt.Println("(set, not shown)")
			}
			return nil
		}
		fmt.Println(v)
		return nil
	case len(rest) == 3 && rest[0] == "set":
		v := rest[2]
		if v == "-" {
			b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
			if err != nil {
				return err
			}
			v = strings.TrimSpace(string(b))
		}
		if err := st.SetSetting(ctx, rest[1], v); err != nil {
			return err
		}
		_ = st.Audit(ctx, time.Now(), "cli", "setting.set", rest[1], "")
		fmt.Printf("%s set\n", rest[1])
		return nil
	}
	return fmt.Errorf("usage: excubra server setting get <key> | set <key> <value|->")
}

// remoteCmd: excubra server remote test | status — the operator stack from a shell.
func remoteCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server remote", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	st, _, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	svc := remote.New(st, nil)
	switch {
	case len(rest) == 1 && rest[0] == "test":
		set := svc.Settings(ctx)
		n, err := svc.Test(ctx)
		if err != nil {
			return fmt.Errorf("operator stack %s: %w", orDash(set.URL), err)
		}
		fmt.Printf("operator stack %s: ok, %d groups (technicians=%s, lans=%s, boxes=%s)\n", set.URL, n, set.TechGroup, set.LANGroup, set.BoxGroup)
		return nil
	case len(rest) == 3 && rest[0] == "enable":
		ra, err := svc.Enable(ctx, rest[1], rest[2], "cli")
		if err != nil {
			return err
		}
		fmt.Printf("%s\t%s\tstate=%s\t%s\n", ra.SiteID, ra.CIDR, ra.State, ra.Detail)
		return nil
	case len(rest) == 2 && rest[0] == "disable":
		ra, err := svc.Disable(ctx, rest[1], "cli")
		if err != nil {
			return err
		}
		fmt.Printf("%s\t%s\tstate=%s\n", ra.SiteID, ra.CIDR, ra.State)
		return nil
	case len(rest) == 1 && rest[0] == "peers":
		ps, err := svc.PeerStates(ctx)
		if err != nil {
			return err
		}
		if len(ps) == 0 {
			fmt.Println("(no assigned box)")
			return nil
		}
		for _, p := range ps {
			fmt.Printf("%s\t%s\tsite=%s\toperator=%s\tip=%s\tkey=%s\n", p.BoxID, orDash(p.BoxName), p.SiteID, p.Status, orDash(p.IP), p.Key)
		}
		return nil
	case len(rest) == 1 && rest[0] == "reconcile":
		svc.Reconcile(ctx)
		fallthrough
	case len(rest) == 1 && rest[0] == "status":
		rows, err := st.RemoteAccesses(ctx)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("(no site has remote access)")
			return nil
		}
		for _, r := range rows {
			fmt.Printf("%s\t%s\tenabled=%v\tstate=%s\tpeer=%s\t%s\n", r.SiteID, r.CIDR, r.Enabled, r.State, orDash(r.PeerIP), r.Detail)
		}
		return nil
	}
	return fmt.Errorf("usage: excubra server remote test | status | peers | reconcile | enable <site_id> <cidr> | disable <site_id>")
}

// aiCmd runs an assessment from the shell, or checks the provider.
func aiCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server ai", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	file := fs.String("file", "-", "import: JSON answer in the agreed shape; - reads stdin")
	by := fs.String("by", "cli", "import: who wrote it")
	model := fs.String("model", "session", "import: which model or person")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	st, cfg, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	loc, _ := time.LoadLocation(cfg.Timezone)
	svc := ai.New(st, nil, loc)
	switch {
	case len(rest) == 1 && rest[0] == "test":
		reply, err := svc.Test(ctx)
		if err != nil {
			return err
		}
		set := svc.Settings(ctx)
		fmt.Printf("%s %s answers: %s\n", set.Provider, set.Model, reply)
		return nil
	case len(rest) == 2 && rest[0] == "packet":
		// the situation as the model would see it, for a person or a session model
		pk, err := svc.Packet(ctx, rest[1])
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", " ")
		return enc.Encode(pk)
	case len(rest) == 2 && rest[0] == "import":
		// import <site_id> [--file result.json] [--by actor] [--model label]: an assessment written outside
		var data []byte
		if *file == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(*file) //nolint:gosec // the operator names the file
		}
		if err != nil {
			return err
		}
		r, err := ai.ParseResult(string(data))
		if err != nil {
			return fmt.Errorf("ai import: %w", err)
		}
		brief, err := svc.Import(ctx, rest[1], *by, "session", *model, r, 0)
		if err != nil {
			return err
		}
		fmt.Printf("brief %s stored: risk=%s priorities=%d findings=%d\n", brief.ID, brief.Risk, len(r.Priorities), len(r.Findings))
		return nil
	case len(rest) == 2 && rest[0] == "assess":
		brief, err := svc.Assess(ctx, rest[1], "cli")
		if err != nil {
			return err
		}
		var r ai.Result
		_ = json.Unmarshal(brief.Body, &r)
		fmt.Printf("risk=%s model=%s sent=%dB got=%dB in %dms\n%s\n", brief.Risk, brief.Model, brief.PromptBytes, brief.ResponseBytes, brief.DurationMS, brief.Summary)
		for i, p := range r.Priorities {
			fmt.Printf("%d. [%s] %s — %s\n", i+1, p.Severity, p.Title, p.Action)
		}
		fmt.Printf("%d findings from the model\n", len(r.Findings))
		return nil
	}
	return fmt.Errorf("usage: excubra server ai test | assess <site_id> | packet <site_id> | import <site_id> [--file f.json] [--by who] [--model label]")
}

// mcpCmd serves EX0 over the Model Context Protocol on stdin/stdout — started
// through SSH from a machine in the operator overlay, nothing new listens.
func mcpCmd(args []string) error {
	fs := flag.NewFlagSet("excubra server mcp", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "server env file")
	actor := fs.String("actor", "mcp", "who the assistant acts for, in audits")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, cfg, err := cliStore(*envFile)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	loc, _ := time.LoadLocation(cfg.Timezone)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	srv := &mcp.Server{Store: st, AI: ai.New(st, log, loc), Log: log, Now: time.Now, Actor: *actor}
	return srv.Serve(context.Background(), os.Stdin, os.Stdout)
}
