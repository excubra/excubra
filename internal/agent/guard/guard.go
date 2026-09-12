// Package guard keeps a packet from the network from taking the agent down: a
// panic while parsing one query, one frame or one connection is logged and
// swallowed, the goroutine ends, the agent goes on. The box must never lose
// its monitoring to a malformed packet (ADR-0007: it may never do harm — to
// itself either).
package guard

import (
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

var (
	mu       sync.Mutex
	lastLog  time.Time
	swallowd int
)

// Recover is deferred at the top of a goroutine that handles input from the
// network. It logs a panic at most once a minute (with a count of what it
// swallowed since) and returns normally.
func Recover(log *slog.Logger, what string) {
	r := recover()
	if r == nil {
		return
	}
	mu.Lock()
	swallowd++
	n := swallowd
	quiet := time.Since(lastLog) < time.Minute
	if !quiet {
		lastLog = time.Now()
		swallowd = 0
	}
	mu.Unlock()
	if quiet {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	log.Error("recovered from a panic while handling network input", "what", what, "panic", r, "since_last_log", n, "stack", string(debug.Stack()))
}
