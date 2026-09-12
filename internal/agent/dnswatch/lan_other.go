//go:build !linux

package dnswatch

// Off Linux there is no route table to read: the sensor listens nowhere unless a
// test names an address.
func platformLAN() string { return "" }
