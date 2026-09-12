package agent

import (
	"strings"
	"testing"
)

func TestParseCaps(t *testing.T) {
	if got := strings.Join(parseCaps("0000000000002000"), ","); got != "CAP_NET_RAW" { // the KfT box of 12.09.2026
		t.Fatalf("raw only: %s", got)
	}
	if got := strings.Join(parseCaps("0000000000002400"), ","); got != "CAP_NET_BIND_SERVICE,CAP_NET_RAW" {
		t.Fatalf("both: %s", got)
	}
	if got := parseCaps("0"); len(got) != 0 {
		t.Fatalf("none: %v", got)
	}
	if got := parseCaps("zz"); got != nil {
		t.Fatalf("garbage: %v", got)
	}
}
