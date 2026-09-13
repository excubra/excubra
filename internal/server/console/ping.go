package console

import (
	"context"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// The state badge says whether a device answers right now. It does not say
// whether it answered all night, and "erreichbar" on a device that dropped out
// eleven times since breakfast is the most misleading word in the console.
//
// So every monitored device carries its last day of pings: the share of rounds
// that succeeded, the round trip of the last one, and twenty-four hourly values
// for the little bar chart in the row and on the card. It is built from the same
// rollups the availability chart uses — one query for the whole site, not one per
// device.

// pingHours is how many hourly buckets a device carries. A day fits in a row.
const pingHours = 24

// noData marks an hour nobody measured; the bar is drawn empty rather than as a
// failure, because "we did not look" and "it was down" are different answers.
const noData = -1

// ping is a device's last day of reachability.
type ping struct {
	Pct    float64 `json:"pct"`    // share of rounds that succeeded, 0..100
	Rounds int     `json:"rounds"` // how many rounds went into that
	Failed int     `json:"failed"`
	AvgMS  int     `json:"avgMs"`  // average round trip over the window, -1 when unmeasured
	LastMS int     `json:"lastMs"` // the last round's round trip, -1 when unmeasured
	Hours  []int   `json:"hours"`  // pingHours values: percent per hour, -1 = nobody looked
}

// pingsForSite builds one ping per host from a single pass over the tenant's
// rollups. Callers pass the site's hosts; hosts of other sites are dropped.
func (s *Server) pingsForSite(ctx context.Context, tenantID string, hostIDs map[string]bool, now time.Time) map[string]ping {
	out := map[string]ping{}
	if len(hostIDs) == 0 {
		return out
	}
	from := now.Add(-pingHours * time.Hour)
	rollups, err := s.Store.Rollups(ctx, tenantID, "", from, now)
	if err != nil {
		s.Log.Warn("ping history", "tenant", tenantID, "err", err)
		return out
	}
	start := now.UTC().Truncate(time.Hour).Add(-(pingHours - 1) * time.Hour)

	type acc struct {
		rounds, failed        int
		latSum                int64
		latRounds             int
		hourRounds, hourFails [pingHours]int
	}
	byHost := map[string]*acc{}
	for _, ru := range rollups {
		if !hostIDs[ru.HostID] {
			continue
		}
		a := byHost[ru.HostID]
		if a == nil {
			a = &acc{}
			byHost[ru.HostID] = a
		}
		a.rounds += ru.Rounds
		a.failed += ru.Failed
		if ru.LatencySumMS > 0 && ru.Rounds > ru.Failed {
			a.latSum += ru.LatencySumMS
			a.latRounds += ru.Rounds - ru.Failed
		}
		if i := int(ru.Hour.Sub(start) / time.Hour); i >= 0 && i < pingHours {
			a.hourRounds[i] += ru.Rounds
			a.hourFails[i] += ru.Failed
		}
	}

	for id, a := range byHost {
		p := ping{Rounds: a.rounds, Failed: a.failed, AvgMS: noData, LastMS: noData, Pct: 100}
		if a.rounds > 0 {
			p.Pct = 100 * float64(a.rounds-a.failed) / float64(a.rounds)
		}
		if a.latRounds > 0 {
			p.AvgMS = int(a.latSum / int64(a.latRounds))
		}
		p.Hours = make([]int, pingHours)
		for i := 0; i < pingHours; i++ {
			if a.hourRounds[i] == 0 {
				p.Hours[i] = noData
				continue
			}
			p.Hours[i] = int(100 * float64(a.hourRounds[i]-a.hourFails[i]) / float64(a.hourRounds[i]))
		}
		out[id] = p
	}
	return out
}

// lastRoundTrip is what the newest round measured: the ICMP check when there is
// one, else the first check that answered. A device reached only over TCP still
// has a number worth showing.
func lastRoundTrip(checks []wire.CheckResult) int {
	best := noData
	for _, c := range checks {
		if !c.OK || c.LatencyMS == nil || *c.LatencyMS < 0 {
			continue
		}
		ms := int(*c.LatencyMS)
		if c.Type == wire.CheckICMP {
			return ms
		}
		if best == noData {
			best = ms
		}
	}
	return best
}

// withLastRound fills in the newest measurement, which lives in the host's state
// rather than in the rollups.
func withLastRound(p ping, h hostRow) ping {
	p.LastMS = lastRoundTrip(h.State.LastChecks)
	if p.Hours == nil {
		// A host watched since the last rollup has no history yet; an empty day is
		// still a day, and the bar draws it as "nobody looked" rather than nothing.
		p.Hours = make([]int, pingHours)
		for i := range p.Hours {
			p.Hours[i] = noData
		}
		p.AvgMS, p.Pct = noData, 100
	}
	return p
}
