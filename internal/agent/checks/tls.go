package checks

import "crypto/tls"

// insecureTLS is the client config for http checks. Verification is deliberately
// off: the question is whether the device answers, and LAN devices carry
// self-signed certificates. No response body is read and nothing is stored.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // see above: reachability check, not a trust decision
}
