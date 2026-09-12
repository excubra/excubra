//go:build linux

package dnswatch

import "github.com/excubra/excubra/internal/agent/discovery"

// platformLAN is the address of the default-route interface.
func platformLAN() string {
	_, prefix, err := discovery.LANInterface()
	if err != nil {
		return ""
	}
	return prefix.Addr().String()
}
