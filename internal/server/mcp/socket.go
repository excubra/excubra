package mcp

// The MCP server lives inside the running server (ADR-0024). A session still
// starts `excubra server mcp` through SSH and talks to it over stdio — but that
// command no longer answers by itself: it carries the session's lines to a Unix
// socket in the server's data directory and the answers back.
//
// Why: a second process sees the files, not the server. It could not open the
// sealed CA key (so it minted no enrollment keys), and whatever it wrote into
// the store went past the engine, which holds sites, hosts and their states in
// memory. Inside the server the tools are the console's own functions, with
// the same audit trail.
//
// Nothing new listens on a network: the socket is a file in a directory only
// the service user and root can enter.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// SocketName is the socket's file name inside the server's data directory.
const SocketName = "mcp.sock"

// helloWord opens every connection: a line that says who the session acts for.
const helloWord = "ex0-mcp"

type hello struct {
	Hello string `json:"hello"`
	Actor string `json:"actor"`
}

// ServeSocket answers MCP on a Unix socket until ctx ends. Every connection is
// one session: its first line names the actor, everything after is served
// exactly like stdio.
func (s *Server) ServeSocket(ctx context.Context, path string) error {
	// A socket left behind by a server that was killed: the data directory is
	// ours alone, so whatever is at this path is our own leftover.
	_ = os.Remove(path)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return fmt.Errorf("mcp socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("mcp socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = os.Remove(path)
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if s.Log != nil {
				s.Log.Warn("mcp socket: accept", "err", err)
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		go s.serveConn(ctx, conn)
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReaderSize(conn, 64<<10)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	var h hello
	if json.Unmarshal([]byte(line), &h) != nil || h.Hello != helloWord {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	session := *s // same store, engine and services; its own actor
	session.Actor = cleanActor(h.Actor)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = session.Serve(ctx, br, conn)
}

// cleanActor keeps an actor to what an audit line can carry.
func cleanActor(a string) string {
	a = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == '@':
			return r
		}
		return -1
	}, a)
	if len(a) > 64 {
		a = a[:64]
	}
	if a == "" {
		return "mcp"
	}
	return a
}

// How long a request waits for a server that is restarting. A release swaps the
// binary and systemd starts the new one within seconds; a minute covers a slow
// start and still ends before a session gives up on the tool.
var reconnectFor = time.Minute

// Proxy carries one session's stdio to the running server and back. A request
// that meets a restarting server waits for it and is sent again on a new
// connection, so a session that is setting a customer up survives the very
// release it may be waiting for.
func Proxy(ctx context.Context, path, actor string, in io.Reader, out io.Writer) error {
	p := &proxy{path: path, actor: actor}
	defer p.close()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(line, &probe)
		wantsAnswer := len(probe.ID) > 0 && string(probe.ID) != "null"
		resp, err := p.roundTrip(ctx, line, wantsAnswer, probe.Method != "tools/call")
		if !wantsAnswer {
			continue
		}
		if err != nil {
			resp = unavailable(probe.ID, probe.Method, err)
		}
		if _, err := out.Write(append(resp, '\n')); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Reachable reports whether a server answers on the socket right now.
func Reachable(ctx context.Context, path string) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

type proxy struct {
	path, actor string
	conn        net.Conn
	r           *bufio.Reader
}

func (p *proxy) close() {
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn, p.r = nil, nil
	}
}

func (p *proxy) dial(ctx context.Context) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", p.path)
	if err != nil {
		return err
	}
	h, _ := json.Marshal(hello{Hello: helloWord, Actor: p.actor})
	if _, err := conn.Write(append(h, '\n')); err != nil {
		_ = conn.Close()
		return err
	}
	p.conn, p.r = conn, bufio.NewReaderSize(conn, 64<<10)
	return nil
}

// alive tells a connection whose server is gone from one that is merely quiet:
// the server never speaks unasked, so the only thing a read can find is the end.
func (p *proxy) alive() bool {
	if p.conn == nil {
		return false
	}
	_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	_, err := p.r.Peek(1)
	_ = p.conn.SetReadDeadline(time.Time{})
	var ne net.Error
	return err == nil || (errors.As(err, &ne) && ne.Timeout())
}

// roundTrip sends one line and reads its answer. Before sending it makes sure
// the connection is alive, waiting for a restarting server if it has to. Once a
// request has left on a live connection it is sent again only if repeating it
// is harmless (repeatable): a tool call that died half-way may have happened.
func (p *proxy) roundTrip(ctx context.Context, line []byte, wantsAnswer, repeatable bool) ([]byte, error) {
	deadline := time.Now().Add(reconnectFor)
	wait := 250 * time.Millisecond
	for {
		if !p.alive() {
			p.close()
			if err := p.dial(ctx); err != nil {
				if time.Now().After(deadline) || ctx.Err() != nil {
					return nil, fmt.Errorf("the server does not answer on its socket (%w)", err)
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(wait):
				}
				if wait < 3*time.Second {
					wait *= 2
				}
				continue
			}
		}
		_, werr := p.conn.Write(append(append([]byte(nil), line...), '\n'))
		if werr == nil {
			if !wantsAnswer {
				return nil, nil
			}
			resp, rerr := p.r.ReadBytes('\n')
			if rerr == nil {
				return bytes.TrimRight(resp, "\r\n"), nil
			}
			p.close()
			if !repeatable {
				return nil, errors.New("the server went away while it was answering; it may have carried the request out — look at the state before repeating it")
			}
		} else {
			p.close()
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, errors.New("the server did not come back in time")
		}
		// a server that accepts and hangs up at once must not spin us
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// unavailable is the answer when the server cannot be reached: a tool result a
// session can read for a tool call, a protocol error for everything else.
func unavailable(id json.RawMessage, method string, err error) []byte {
	msg := "EX0 server nicht erreichbar: " + err.Error()
	var res response
	res.JSONRPC, res.ID = "2.0", id
	if method == "tools/call" {
		res.Result = map[string]any{"content": []map[string]any{{"type": "text", "text": "Fehler: " + msg}}, "isError": true}
	} else {
		res.Error = &rpcError{Code: -32000, Message: msg}
	}
	b, _ := json.Marshal(res)
	return b
}
