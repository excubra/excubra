//go:build !linux

package checks

import (
	"context"
	"errors"
	"time"
)

// unsupportedPinger stands in on platforms without the Linux ICMP path. The agent
// still builds and runs on macOS for development; icmp checks report an error
// instead of silently passing.
type unsupportedPinger struct{}

// NewPinger returns a pinger that always fails on this platform.
func NewPinger() Pinger { return unsupportedPinger{} }

func (unsupportedPinger) Ping(context.Context, string) (time.Duration, error) {
	return 0, errors.New("icmp checks need Linux (this build has no ICMP socket)")
}
