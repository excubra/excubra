package guard

import (
	"log/slog"
	"testing"
)

func TestRecoverSwallowsAPanic(t *testing.T) {
	done := make(chan bool)
	go func() {
		defer func() { done <- true }()
		defer Recover(slog.Default(), "test")
		var m []byte
		_ = m[3] // out of range
	}()
	if !<-done {
		t.Fatal("goroutine did not finish")
	}
	// no panic: nothing to do
	func() {
		defer Recover(nil, "quiet")
	}()
}
