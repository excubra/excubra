import { cn } from "@/lib/utils"
import type { Ping } from "@/lib/api"

// "erreichbar" says a device answered the last round. It does not say whether it
// answered all night, and that is the difference between a device that is fine
// and one that drops out eleven times a day. So a monitored device carries its
// last twenty-four hours as a row of small bars: one per hour, height and colour
// from the share of rounds that succeeded, grey where nobody looked.
//
// It is a glance, not a chart. The numbers beside it say the rest, and the
// device's own page has the real chart.

const barCount = 24

/** An hour nobody measured. The server sends -1; grey is not the same as failed. */
const noData = -1

function toneOf(pct: number): string {
  if (pct < 0) return "bg-muted"
  if (pct >= 99.5) return "bg-primary/70"
  if (pct >= 90) return "bg-primary/40"
  return "bg-destructive/80"
}

/** The bars alone, for places where the numbers are written elsewhere. */
export function PingBar({ hours, className }: { hours?: number[] | null; className?: string }) {
  const day = hours && hours.length ? hours : Array<number>(barCount).fill(noData)
  return (
    <span className={cn("inline-flex h-4 items-end gap-px", className)} aria-hidden="true">
      {day.map((pct, i) => (
        <span
          key={i}
          className={cn("w-[3px] rounded-[1px]", toneOf(pct))}
          // an hour with data is never shorter than a quarter, so a bad hour is
          // still visible rather than a gap
          style={{ height: pct < 0 ? "25%" : `${Math.max(25, pct)}%` }}
        />
      ))}
    </span>
  )
}

/** How long ago the last round trip was, in the words an operator uses. */
function latency(p: Ping): string {
  if (p.lastMs >= 0) return `${p.lastMs} ms`
  if (p.avgMs >= 0) return `${p.avgMs} ms ⌀`
  return "–"
}

/** Availability as a percentage, with the precision the number deserves. */
export function pingPct(p: Ping): string {
  if (p.rounds === 0) return "noch keine Runde"
  const v = p.pct
  // 99.97 % rounds to 100 % and reads as "nothing happened", which is a lie when
  // something did: anything short of perfect keeps a decimal.
  return v >= 100 ? "100 %" : `${v.toFixed(1).replace(".", ",")} %`
}

/**
 * PingCell is the bars plus the two numbers that matter: how much of the day the
 * device answered, and how fast it answered last.
 */
export function PingCell({ ping, className }: { ping?: Ping | null; className?: string }) {
  if (!ping) return <span className={cn("text-xs text-muted-foreground", className)}>nicht beobachtet</span>
  const title = ping.rounds
    ? `${ping.rounds - ping.failed} von ${ping.rounds} Prüfungen in 24 h erfolgreich`
    : "seit dem Einschalten noch keine abgeschlossene Runde"
  return (
    <span className={cn("flex items-center gap-2", className)} title={title}>
      <PingBar hours={ping.hours} />
      <span className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
        {pingPct(ping)}
        {ping.rounds > 0 && <> · {latency(ping)}</>}
      </span>
    </span>
  )
}
