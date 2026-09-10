package discovery

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterPaces(t *testing.T) {
	r := newRateLimiter(100) // 10 ms apart
	start := time.Now()
	for i := 0; i < 5; i++ {
		if !r.wait(context.Background()) {
			t.Fatal("wait returned false without cancellation")
		}
	}
	if d := time.Since(start); d < 35*time.Millisecond {
		t.Fatalf("5 sends at 100 pps took only %v", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.next = time.Now().Add(time.Hour)
	if r.wait(ctx) {
		t.Fatal("wait ignored a cancelled context")
	}
	if newRateLimiter(0).interval != time.Second/DefaultMaxPPS {
		t.Fatal("zero pps did not fall back to the default")
	}
}
