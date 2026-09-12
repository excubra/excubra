package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Forward relays every TCP connection accepted on ln to target until ctx ends. It
// runs inside the operator's network namespace (netbird-operator-ssh.service,
// ADR-0016), where the box's overlay address lives, and hands the connections to
// the box's own sshd in the root namespace over the veth pair. No parsing, no
// buffering beyond the kernel's, at most maxForwardConns at a time.
func Forward(ctx context.Context, ln net.Listener, target string, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return errors.New("forward: target must be host:port")
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	sem := make(chan struct{}, maxForwardConns)
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			wg.Wait()
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			log.Warn("forward: too many connections, refusing", "from", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			relay(ctx, conn, target, log)
		}()
	}
}

const (
	maxForwardConns = 64
	forwardDial     = 10 * time.Second
)

func relay(ctx context.Context, conn net.Conn, target string, log *slog.Logger) {
	defer func() { _ = conn.Close() }()
	d := net.Dialer{Timeout: forwardDial}
	up, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Warn("forward: target unreachable", "target", target, "from", conn.RemoteAddr(), "err", err)
		return
	}
	defer func() { _ = up.Close() }()
	for _, c := range []net.Conn{conn, up} {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(30 * time.Second)
		}
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // pass the half-close on, sshd relies on it
		}
		done <- struct{}{}
	}
	go pipe(up, conn)
	go pipe(conn, up)
	select {
	case <-done:
		// one direction ended: give the other a moment to drain, then tear down
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
	case <-ctx.Done():
	}
}
