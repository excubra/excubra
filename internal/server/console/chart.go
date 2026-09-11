package console

import (
	"context"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/server/store"
)

// chartBucket is one column of the availability chart: check rounds of one hour (or one
// day for the 7-day view), split into ok and failed.
type chartBucket struct {
	Label  string
	At     time.Time
	OK     int
	Failed int
}

type chartData struct {
	Range      string // 24h | 7d
	AxisLabels []string
	Buckets    []chartBucket
	Rounds     int
	Failed     int
	Pct        float64 // availability over the range
	Hosts      int     // hosts with at least one round
}

// buildChart sums the check rollups of the given tenants (hostID "" = every host, or one
// host) into hourly buckets for 24h or daily buckets for 7d.
func (s *Server) buildChart(ctx context.Context, tenantIDs []string, hostID, rng string, now time.Time) (chartData, error) {
	d := chartData{Range: "24h"}
	n, step := 24, time.Hour
	if rng == "7d" {
		d.Range, n, step = "7d", 7, 24*time.Hour
	}
	var start time.Time
	if step == time.Hour {
		start = now.UTC().Truncate(time.Hour).Add(-time.Duration(n-1) * time.Hour)
	} else {
		y, m, dd := now.In(s.Loc).Date()
		start = time.Date(y, m, dd, 0, 0, 0, 0, s.Loc).AddDate(0, 0, -(n - 1))
	}
	d.Buckets = make([]chartBucket, n)
	for i := range d.Buckets {
		at := start.Add(time.Duration(i) * step)
		lbl := at.In(s.Loc).Format("15:04")
		if step > time.Hour {
			lbl = at.In(s.Loc).Format("02.01.")
		}
		d.Buckets[i] = chartBucket{Label: lbl, At: at}
	}
	hosts := map[string]bool{}
	for _, tid := range tenantIDs {
		rollups, err := s.Store.Rollups(ctx, tid, hostID, start, now.Add(time.Hour))
		if err != nil {
			return d, err
		}
		for _, ru := range rollups {
			var idx int
			if step == time.Hour {
				idx = int(ru.Hour.Sub(start) / time.Hour)
			} else {
				idx = int(ru.Hour.In(s.Loc).Sub(start).Hours() / 24)
			}
			if idx < 0 || idx >= n {
				continue
			}
			d.Buckets[idx].OK += ru.Rounds - ru.Failed
			d.Buckets[idx].Failed += ru.Failed
			d.Rounds += ru.Rounds
			d.Failed += ru.Failed
			hosts[ru.HostID] = true
		}
	}
	d.Hosts = len(hosts)
	step2 := 1
	if n > 8 {
		step2 = (n + 6) / 7
	}
	for i := 0; i < n; i += step2 {
		d.AxisLabels = append(d.AxisLabels, d.Buckets[i].Label)
	}
	if last := d.Buckets[n-1].Label; d.AxisLabels[len(d.AxisLabels)-1] != last {
		d.AxisLabels = append(d.AxisLabels, last)
	}
	d.Pct = 100
	if d.Rounds > 0 {
		d.Pct = 100 * float64(d.Rounds-d.Failed) / float64(d.Rounds)
	}
	return d, nil
}

// areaSVG draws the stacked area chart (ok in green, failed in red on top) as inline SVG,
// in the manner of the shadcn dashboard: dashed horizontal grid, no vertical lines,
// muted axis labels, gradient fills. Colors come from the CSS variables.
func areaSVG(c chartData) template.HTML {
	const w, h = 1000.0, 260.0
	const padL, padR, padT, padB = 8.0, 8.0, 12.0, 28.0
	n := len(c.Buckets)
	if n == 0 {
		return ""
	}
	maxV := 1
	for _, b := range c.Buckets {
		if v := b.OK + b.Failed; v > maxV {
			maxV = v
		}
	}
	plotW, plotH := w-padL-padR, h-padT-padB
	x := func(i int) float64 {
		if n == 1 {
			return padL + plotW/2
		}
		return padL + plotW*float64(i)/float64(n-1)
	}
	y := func(v int) float64 { return padT + plotH - plotH*float64(v)/float64(maxV) }
	var top, mid strings.Builder // top = ok+failed, mid = failed only
	for i, b := range c.Buckets {
		fmt.Fprintf(&top, "%s%.1f,%.1f", sep(i), x(i), y(b.OK+b.Failed))
		fmt.Fprintf(&mid, "%s%.1f,%.1f", sep(i), x(i), y(b.Failed))
	}
	base := fmt.Sprintf("%.1f,%.1f %.1f,%.1f", x(n-1), y(0), x(0), y(0))
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg class="chart" viewBox="0 0 %.0f %.0f" preserveAspectRatio="none" role="img" aria-label="Prüfungen je Stunde, erreichbar und ausgefallen">`, w, h))
	sb.WriteString(`<defs><linearGradient id="gOk" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stop-color="var(--ok)" stop-opacity=".8"/><stop offset="95%" stop-color="var(--ok)" stop-opacity=".1"/></linearGradient><linearGradient id="gBad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stop-color="var(--bad)" stop-opacity=".8"/><stop offset="95%" stop-color="var(--bad)" stop-opacity=".1"/></linearGradient></defs>`)
	for _, f := range []float64{0.25, 0.5, 0.75, 1} {
		gy := padT + plotH - plotH*f
		sb.WriteString(fmt.Sprintf(`<line x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f" class="grid"/>`, padL, w-padR, gy, gy))
	}
	sb.WriteString(fmt.Sprintf(`<polygon class="area ok" fill="url(#gOk)" points="%s %s"/>`, top.String(), base))
	sb.WriteString(fmt.Sprintf(`<polyline class="line ok" fill="none" points="%s"/>`, top.String()))
	if c.Failed > 0 {
		sb.WriteString(fmt.Sprintf(`<polygon class="area bad" fill="url(#gBad)" points="%s %s"/>`, mid.String(), base))
		sb.WriteString(fmt.Sprintf(`<polyline class="line bad" fill="none" points="%s"/>`, mid.String()))
	}
	sb.WriteString("</svg>")
	return template.HTML(sb.String()) //nolint:gosec // built from numbers and escaped labels only
}

func sep(i int) string {
	if i == 0 {
		return ""
	}
	return " "
}

// tenantIDs lists the ids of the given tenants.
func tenantIDs(ts []store.Tenant) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return out
}
