package checks

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// fakePinger answers according to a table, so the round logic is testable off Linux.
type fakePinger struct {
	up  map[string]time.Duration
	err error
}

func (f fakePinger) Ping(_ context.Context, address string) (time.Duration, error) {
	if f.err != nil {
		return 0, f.err
	}
	if d, ok := f.up[address]; ok {
		return d, nil
	}
	return 0, errors.New("i/o timeout")
}

func TestRoundICMP(t *testing.T) {
	r := NewRunner(fakePinger{up: map[string]time.Duration{"10.0.0.1": 3 * time.Millisecond}})
	host := wire.HostConfig{HostID: "host_a", Address: "10.0.0.1", Checks: []wire.CheckConfig{{Type: wire.CheckICMP}}}
	round := r.Round(context.Background(), host)
	if !round.OK || len(round.Checks) != 1 || round.Checks[0].Type != "icmp" || round.Checks[0].LatencyMS == nil || *round.Checks[0].LatencyMS != 3 {
		t.Fatalf("ok round: %+v", round)
	}
	host.Address = "10.0.0.9"
	round = r.Round(context.Background(), host)
	if round.OK || round.Checks[0].Error != "timeout" {
		t.Fatalf("failed round: %+v", round.Checks[0])
	}
}

func TestRoundTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	r := NewRunner(nil)
	host := wire.HostConfig{Address: "127.0.0.1", Checks: []wire.CheckConfig{{Type: wire.CheckTCP, Port: port}}}
	round := r.Round(context.Background(), host)
	if !round.OK || round.Checks[0].Type != "tcp:"+portStr {
		t.Fatalf("open port: %+v", round.Checks[0])
	}
	_ = ln.Close()
	round = r.Round(context.Background(), host)
	if round.OK || round.Checks[0].Error == "" {
		t.Fatalf("closed port: %+v", round.Checks[0])
	}
	// a bad port never leaves the agent
	round = r.Round(context.Background(), wire.HostConfig{Address: "127.0.0.1", Checks: []wire.CheckConfig{{Type: wire.CheckTCP, Port: 0}}})
	if round.OK || round.Checks[0].Error != "port out of range" {
		t.Fatalf("bad port: %+v", round.Checks[0])
	}
}

func TestRoundHTTP(t *testing.T) {
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("a body the agent must not keep"))
	}))
	defer srv.Close()
	r := NewRunner(nil)
	host := wire.HostConfig{Address: "127.0.0.1", Checks: []wire.CheckConfig{{Type: wire.CheckHTTP, URL: srv.URL}}}

	round := r.Round(context.Background(), host)
	if !round.OK || round.Checks[0].Status != 200 {
		t.Fatalf("200: %+v", round.Checks[0])
	}
	status = 500
	round = r.Round(context.Background(), host)
	if round.OK || !strings.Contains(round.Checks[0].Error, "outside 200..399") {
		t.Fatalf("500: %+v", round.Checks[0])
	}
	// an explicit expectation wins
	host.Checks[0].ExpectStatus = []int{500, 500}
	if round = r.Round(context.Background(), host); !round.OK {
		t.Fatalf("expect 500: %+v", round.Checks[0])
	}
	// redirects are not followed: a 302 is a 302
	status = 302
	host.Checks[0].ExpectStatus = nil
	if round = r.Round(context.Background(), host); !round.OK || round.Checks[0].Status != 302 {
		t.Fatalf("302: %+v", round.Checks[0])
	}
	srv.Close()
	if round = r.Round(context.Background(), host); round.OK {
		t.Fatal("dead server reported ok")
	}
}

func TestRoundCombinesChecks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	r := NewRunner(fakePinger{up: map[string]time.Duration{"127.0.0.1": time.Millisecond}})
	host := wire.HostConfig{Address: "127.0.0.1", Checks: []wire.CheckConfig{
		{Type: wire.CheckICMP},
		{Type: wire.CheckHTTP, URL: srv.URL},
		{Type: wire.CheckTCP, Port: 1},
	}}
	round := r.Round(context.Background(), host)
	if round.OK {
		t.Fatal("a round with one failing check must not be ok")
	}
	if len(round.Checks) != 3 || !round.Checks[0].OK || !round.Checks[1].OK || round.Checks[2].OK {
		t.Fatalf("results out of order or wrong: %+v", round.Checks)
	}
	// results keep the configured order, which the console shows
	if round.Checks[0].Type != "icmp" || round.Checks[1].Type != "http" || round.Checks[2].Type != "tcp:1" {
		t.Fatalf("order: %+v", round.Checks)
	}
}

func TestRoundWithoutChecks(t *testing.T) {
	r := NewRunner(nil)
	round := r.Round(context.Background(), wire.HostConfig{Address: "10.0.0.1"})
	if round.OK || round.Checks[0].Error == "" {
		t.Fatalf("no checks: %+v", round)
	}
}

func TestUnknownTypeNeverRuns(t *testing.T) {
	r := NewRunner(nil)
	// this is what a server asking for something else would look like
	round := r.Round(context.Background(), wire.HostConfig{Address: "127.0.0.1", Checks: []wire.CheckConfig{{Type: "portscan"}}})
	if round.OK || round.Checks[0].Error != "unsupported check type" {
		t.Fatalf("unsupported type: %+v", round.Checks[0])
	}
}

func TestValidate(t *testing.T) {
	errs := Validate([]wire.HostConfig{
		{HostID: "host_ok", Checks: []wire.CheckConfig{{Type: wire.CheckICMP}, {Type: wire.CheckTCP, Port: 443}, {Type: wire.CheckHTTP, URL: "https://x"}}},
		{HostID: "host_bad", Checks: []wire.CheckConfig{{Type: wire.CheckTCP}, {Type: wire.CheckHTTP}, {Type: "snmp"}}},
	})
	if len(errs) != 3 {
		t.Fatalf("errors: %v", errs)
	}
	for _, want := range []string{"without a valid port", "without a url", `unknown check type "snmp"`} {
		found := false
		for _, e := range errs {
			if strings.Contains(e, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %q in %v", want, errs)
		}
	}
}

func TestShortErrors(t *testing.T) {
	cases := map[error]string{
		context.DeadlineExceeded: "timeout",
		errors.New("dial tcp 10.0.0.1:443: connect: connection refused"): "connection refused",
		errors.New("dial tcp 10.0.0.1:443: connect: no route to host"):   "no route to host",
		errors.New("lookup nope: no such host"):                          "name does not resolve",
	}
	for err, want := range cases {
		if got := short(err); got != want {
			t.Errorf("short(%v) = %q, want %q", err, got, want)
		}
	}
	long := errors.New(strings.Repeat("x", 200))
	if got := short(long); len(got) != 80 {
		t.Errorf("long error not truncated: %d chars", len(got))
	}
}
