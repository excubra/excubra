// Package version carries build information and the agent/server compatibility rule.
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Set at build time via -ldflags "-X github.com/excubra/excubra/internal/version.Version=…".
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Window is the number of MINOR versions an agent may be away from the server
// (in either direction) and still be accepted. See ADR-0002.
const Window = 2

// String returns the human-readable build description.
func String() string {
	return fmt.Sprintf("excubra %s (commit %s, built %s)", Version, Commit, Date)
}

// Semver is a parsed MAJOR.MINOR.PATCH; pre-release and build metadata are ignored.
type Semver struct {
	Major, Minor, Patch int
}

func (v Semver) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Parse accepts "1.2.3", "v1.2.3", "1.2.3-rc1", "1.2.3+build".
func Parse(s string) (Semver, error) {
	orig := s
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Semver{}, fmt.Errorf("version: %q is not MAJOR.MINOR.PATCH", orig)
	}
	var v Semver
	var err error
	if v.Major, err = strconv.Atoi(parts[0]); err != nil || v.Major < 0 {
		return Semver{}, fmt.Errorf("version: bad major in %q", orig)
	}
	if v.Minor, err = strconv.Atoi(parts[1]); err != nil || v.Minor < 0 {
		return Semver{}, fmt.Errorf("version: bad minor in %q", orig)
	}
	if v.Patch, err = strconv.Atoi(parts[2]); err != nil || v.Patch < 0 {
		return Semver{}, fmt.Errorf("version: bad patch in %q", orig)
	}
	return v, nil
}

// Current returns the running build's version; a dev build parses as 0.0.0.
func Current() Semver {
	v, err := Parse(Version)
	if err != nil {
		return Semver{}
	}
	return v
}

// Compatible reports whether an agent at version a may talk to a server at
// version s: same MAJOR, and the MINOR versions differ by at most Window.
func Compatible(a, s Semver) bool {
	if a.Major != s.Major {
		return false
	}
	d := a.Minor - s.Minor
	if d < 0 {
		d = -d
	}
	return d <= Window
}
