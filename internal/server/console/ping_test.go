package console

import (
	"testing"

	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/wire"
)

func ms(v int64) *int64 { return &v }

// The number an operator reads next to a device is the newest one, and ICMP wins
// over a port check because that is what "ping" means.
func TestLastRoundTrip(t *testing.T) {
	for _, c := range []struct {
		name   string
		checks []wire.CheckResult
		want   int
	}{
		{"icmp wins", []wire.CheckResult{
			{Type: wire.CheckTCP, OK: true, LatencyMS: ms(12)},
			{Type: wire.CheckICMP, OK: true, LatencyMS: ms(3)},
		}, 3},
		{"tcp when there is no icmp", []wire.CheckResult{
			{Type: wire.CheckTCP, OK: true, LatencyMS: ms(12)},
		}, 12},
		{"a failed check has no number", []wire.CheckResult{
			{Type: wire.CheckICMP, OK: false, LatencyMS: ms(0)},
		}, noData},
		{"no measurement at all", []wire.CheckResult{
			{Type: wire.CheckICMP, OK: true},
		}, noData},
		{"nothing ran", nil, noData},
	} {
		if got := lastRoundTrip(c.checks); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// A host that was switched on a minute ago has no rollups yet. It still gets a
// full day of "nobody looked" rather than an empty bar, so the row does not jump
// into shape an hour later.
func TestWithLastRoundFillsAnEmptyDay(t *testing.T) {
	h := hostRow{}
	h.State = state.Host{LastChecks: []wire.CheckResult{{Type: wire.CheckICMP, OK: true, LatencyMS: ms(7)}}}
	p := withLastRound(ping{}, h)
	if p.LastMS != 7 {
		t.Fatalf("last round trip: %d", p.LastMS)
	}
	if len(p.Hours) != pingHours {
		t.Fatalf("a day is %d hours, got %d", pingHours, len(p.Hours))
	}
	for i, v := range p.Hours {
		if v != noData {
			t.Fatalf("hour %d should be unmeasured, got %d", i, v)
		}
	}
	if p.Pct != 100 || p.AvgMS != noData {
		t.Fatalf("an empty day: %+v", p)
	}
}
