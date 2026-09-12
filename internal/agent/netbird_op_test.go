package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// The operator key reaches the second daemon with its own socket, interface and
// port; without that daemon the box says so instead of burning the key.
func TestOperatorKeyGoesToTheSecondDaemon(t *testing.T) {
	w := newWorld(t)
	a := w.agent()
	ctx := context.Background()
	a.heartbeat(ctx)
	must(t, w.eng.AssignBox(ctx, a.st.BoxID, "site_a", "test"))
	must(t, w.st.SetNetbirdKey(ctx, store.NetbirdKey{BoxID: a.st.BoxID, Profile: wire.NetbirdProfileOperator, ManagementURL: "https://viico.vpn.example", SetupKey: "sk-operator", CreatedAt: time.Now()}))

	// no operator daemon on this box: note, key untouched
	a.heartbeat(ctx)
	if k, _ := w.st.NetbirdKeyProfile(ctx, a.st.BoxID, wire.NetbirdProfileOperator); k.ClaimedAt != nil {
		t.Fatal("key claimed although the daemon is missing")
	}
	notes := a.takeNotes()
	if len(notes) != 1 || !strings.Contains(notes[0], "operator daemon is not installed") {
		t.Fatalf("notes: %v", notes)
	}

	// the daemon appears (socket file) — the same fake exec answers it
	sock := filepath.Join(t.TempDir(), "netbird-operator.sock")
	must(t, os.WriteFile(sock, nil, 0o600))
	a.netbirdOp.DaemonAddr = "unix://" + sock
	a.netbirdOp.Binary = "true"
	var ups []string
	a.netbirdOp.Exec = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 2 && args[2] == "up" {
			ups = append(ups, strings.Join(args, " "))
			b, _ := os.ReadFile(args[6])
			ups = append(ups, "key="+string(b))
			return []byte("Connected"), nil
		}
		return []byte(`{"management":{"url":"https://viico.vpn.example","connected":true},"netbirdIp":"100.90.0.7/16","daemonVersion":"0.78.1"}`), nil
	}
	a.heartbeat(ctx)
	if len(ups) != 2 || !strings.Contains(ups[0], "--daemon-addr unix://"+sock+" up --management-url https://viico.vpn.example") || !strings.Contains(ups[0], "--interface-name wt1 --wireguard-port 51821") || ups[1] != "key=sk-operator" {
		t.Fatalf("operator up: %v", ups)
	}
	if k, _ := w.st.NetbirdKeyProfile(ctx, a.st.BoxID, wire.NetbirdProfileOperator); k.ClaimedAt == nil {
		t.Fatal("key not claimed")
	}
	// the next heartbeat carries the second client's state to the server
	a.heartbeat(ctx)
	b, _ := w.st.Box(ctx, a.st.BoxID)
	if b.NetbirdOpStatus != wire.NetbirdConnected || b.NetbirdOpIP != "100.90.0.7" {
		t.Fatalf("operator status server-side: %q %q", b.NetbirdOpStatus, b.NetbirdOpIP)
	}
	// the customer-stack claim is untouched by all this
	if k, err := w.st.NetbirdKey(ctx, a.st.BoxID); err == nil && k.ClaimedAt != nil {
		t.Fatal("customer key touched")
	}
}
