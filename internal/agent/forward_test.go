package agent

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// A line echo server behind the relay: what goes in one side comes out the other,
// half-closes included, and the relay stops when its context ends.
func TestForwardRelaysBothWaysAndStopsWithContext(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					_, _ = c.Write([]byte("echo " + line))
				}
			}()
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- Forward(ctx, ln, echo.Addr().String(), nil) }()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("hallo box\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "echo hallo box\n" {
		t.Fatalf("got %q, %v", line, err)
	}
	// half-close from the client reaches the target: the echo server closes, we see EOF
	_ = c.(*net.TCPConn).CloseWrite()
	if n, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatalf("expected EOF after half-close, read %d bytes", n)
	}

	cancel()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("forward returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forward did not stop with its context")
	}
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond); err == nil {
		t.Fatal("listener still open after stop")
	}
}

func TestForwardRefusesABadTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := Forward(context.Background(), ln, "nohost", nil); err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("expected a host:port error, got %v", err)
	}
}

// A target that is down: the client connection is closed, the relay keeps serving.
func TestForwardClosesWhenTargetIsDown(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := dead.Addr().String()
	_ = dead.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Forward(ctx, ln, target, nil) }()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the relay to close the connection")
	}
}
