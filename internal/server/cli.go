package server

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/auth"
	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/api"
	"github.com/excubra/excubra/internal/server/store"
)

// cliArgs separates positional words from flags, so both
// `tenant list --env-file X` and `tenant --env-file X list` work. Every flag in this
// CLI takes a value, so a bare "-x" consumes the next argument; "-x=y" does not.
func cliArgs(args []string) (positional, flags []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
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
	return st, cfg, err
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
	days := fs.Int("expires-days", 30, "validity in days")
	rest, flags := cliArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 || rest[0] != "new" {
		return fmt.Errorf("usage: excubra server key new [--count N] [--note text] [--expires-days D]")
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
		rec := store.EnrollmentKey{ID: id.New("key"), SecretHash: k.SecretHash(), Note: *note, CreatedAt: now, ExpiresAt: now.Add(time.Duration(*days) * 24 * time.Hour)}
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
	return fmt.Errorf("usage: excubra server tenant add <slug> <name> | list")
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
			fmt.Printf("%s\t%s\t%s\n", s.ID, s.TenantID, s.Name)
		}
		return nil
	}
	return fmt.Errorf("usage: excubra server site add <tenant_id> <slug> <name> | list")
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
