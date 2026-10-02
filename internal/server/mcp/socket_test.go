package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/store"
)

// shortSock gives a socket path that fits into sun_path on every platform; the
// test's own temp directory is too deep for that on macOS.
func shortSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ex0mcp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, SocketName)
}

// session is one stdio session through the proxy: send a line, read its answer.
type session struct {
	t   *testing.T
	in  *io.PipeWriter
	out *bufio.Reader
}

func startSession(t *testing.T, ctx context.Context, sock, actor string) *session {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() { _ = Proxy(ctx, sock, actor, inR, outW); _ = outW.Close() }()
	t.Cleanup(func() { _ = inW.Close() })
	return &session{t: t, in: inW, out: bufio.NewReader(outR)}
}

func (s *session) call(msg string) map[string]any {
	s.t.Helper()
	if _, err := s.in.Write([]byte(msg + "\n")); err != nil {
		s.t.Fatal(err)
	}
	line, err := s.out.ReadString('\n')
	if err != nil {
		s.t.Fatal(err)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(line), &res); err != nil {
		s.t.Fatalf("%v: %s", err, line)
	}
	return res
}

func toolText(t *testing.T, res map[string]any) (string, bool) {
	t.Helper()
	result, _ := res["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content: %v", res)
	}
	isErr, _ := result["isError"].(bool)
	return content[0].(map[string]any)["text"].(string), isErr
}

// The session's command is a pipe into the running server: what it sets up is
// audited under the actor the session named, and the tools are the server's own.
func TestSessionThroughTheSocket(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	srv := &Server{Store: st, Now: func() time.Time { return now }, Actor: "server"}
	sock := shortSock(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.ServeSocket(ctx, sock) }()
	waitFor(t, func() bool { return Reachable(ctx, sock) })
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the socket must be for its owner alone: %v %v", fi, err)
	}

	s := startSession(t, ctx, sock, "jeremia")
	if r, _ := s.call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)["result"].(map[string]any); r["protocolVersion"] != Protocol {
		t.Fatalf("initialize: %v", r)
	}
	// a notification gets no answer and must not shift the answers that follow
	if _, err := s.in.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	text, isErr := toolText(t, s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ex0_create_tenant","arguments":{"slug":"muster","name":"Muster GmbH"}}}`))
	if isErr || !strings.Contains(text, "ten_muster") {
		t.Fatalf("create tenant: %s", text)
	}
	audit, err := st.AuditEntries(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) == 0 || audit[0].Actor != "jeremia" || audit[0].Action != "tenant.create" {
		t.Fatalf("the audit line must name the session's actor, not the server's: %+v", audit)
	}

	// a second session at the same time, with its own actor
	other := startSession(t, ctx, sock, "claude kunde-x")
	text, isErr = toolText(t, other.call(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ex0_create_tenant","arguments":{"slug":"zwei","name":"Zwei AG"}}}`))
	if isErr {
		t.Fatalf("second session: %s", text)
	}
	audit, _ = st.AuditEntries(ctx, 10, 0)
	if audit[0].Actor != "claudekunde-x" {
		t.Fatalf("an actor is cut down to what an audit line carries: %q", audit[0].Actor)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
	if _, err := os.Stat(sock); err == nil {
		t.Fatal("a stopped server must not leave its socket behind")
	}
}

// A release restarts the server. A session that is in the middle of a rollout
// waits for the new one and carries on — on a new connection, without anybody
// noticing more than a pause.
func TestSessionSurvivesARestart(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	srv := &Server{Store: st, Now: time.Now, Actor: "server"}
	sock := shortSock(t)
	old := reconnectFor
	reconnectFor = 5 * time.Second
	t.Cleanup(func() { reconnectFor = old })

	ctx := context.Background()
	first, stopFirst := context.WithCancel(ctx)
	firstDone := make(chan error, 1)
	go func() { firstDone <- srv.ServeSocket(first, sock) }()
	waitFor(t, func() bool { return Reachable(ctx, sock) })

	s := startSession(t, ctx, sock, "jeremia")
	if text, isErr := toolText(t, s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ex0_create_tenant","arguments":{"slug":"vorher","name":"Vorher"}}}`)); isErr {
		t.Fatalf("before the restart: %s", text)
	}

	stopFirst()
	<-firstDone
	// the new server comes up while the request is already waiting
	second, stopSecond := context.WithCancel(ctx)
	defer stopSecond()
	go func() {
		time.Sleep(400 * time.Millisecond)
		_ = srv.ServeSocket(second, sock)
	}()
	text, isErr := toolText(t, s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ex0_create_tenant","arguments":{"slug":"nachher","name":"Nachher"}}}`))
	if isErr || !strings.Contains(text, "ten_nachher") {
		t.Fatalf("after the restart: %s", text)
	}
	if _, err := st.Tenant(ctx, "ten_nachher"); err != nil {
		t.Fatal("the request that waited was not carried out")
	}
}

// No server at all: the session gets an answer it can read, not a hung tool.
func TestNoServerIsAnAnswer(t *testing.T) {
	old := reconnectFor
	reconnectFor = 300 * time.Millisecond
	t.Cleanup(func() { reconnectFor = old })
	sock := shortSock(t)
	ctx := context.Background()
	if Reachable(ctx, sock) {
		t.Fatal("nothing listens there")
	}
	s := startSession(t, ctx, sock, "jeremia")
	text, isErr := toolText(t, s.call(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ex0_overview","arguments":{}}}`))
	if !isErr || !strings.Contains(text, "nicht erreichbar") {
		t.Fatalf("a tool call without a server: %s", text)
	}
	res := s.call(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if res["error"] == nil {
		t.Fatalf("a protocol request without a server is a protocol error: %v", res)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting")
}
