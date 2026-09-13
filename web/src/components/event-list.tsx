import { useNavigate } from "react-router"
import { Bell, CheckCircle2, CircleAlert, CircleMinus, CirclePlus, ShieldAlert, Wifi, WifiOff, Wrench } from "lucide-react"
import { Ago } from "@/components/clock"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { cn } from "@/lib/utils"
import { fmtDateTime } from "@/lib/format"
import type { EventRow } from "@/lib/api"

// One vocabulary for events, in words instead of type names. The server already
// writes the sentence (Title) and the detail (Info); this decides what it looks
// like and what it means.
export const eventKinds: Record<string, { label: string; icon: typeof Bell; tone: "bad" | "good" | "plain"; meaning: string }> = {
  "host.down": { label: "Ausfall", icon: CircleAlert, tone: "bad", meaning: "Ein beobachtetes Gerät hat dreimal hintereinander nicht geantwortet." },
  "host.up": { label: "Wieder da", icon: CheckCircle2, tone: "good", meaning: "Es antwortet wieder, zweimal hintereinander." },
  "box.silent": { label: "Box schweigt", icon: WifiOff, tone: "bad", meaning: "Die Box hat sich dreieinhalb Minuten nicht gemeldet: Strom, Internet oder die Box selbst." },
  "box.back": { label: "Box zurück", icon: Wifi, tone: "good", meaning: "Die Box meldet sich wieder." },
  "device.new": { label: "Neues Gerät", icon: CirclePlus, tone: "plain", meaning: "Ein Gerät ist zum ersten Mal im Kundennetz aufgetaucht." },
  "device.gone": { label: "Gerät weg", icon: CircleMinus, tone: "plain", meaning: "Ein bekanntes Gerät war 14 Tage nicht mehr zu sehen." },
  "security.alert": { label: "Sicherheit", icon: ShieldAlert, tone: "bad", meaning: "Die Live-Erkennung hat etwas gesehen: Köder-Port, Portscan, ARP oder DNS." },
  "maintenance.started": { label: "Wartung an", icon: Wrench, tone: "plain", meaning: "Ein Wartungsfenster läuft; Ausfälle darin lösen nichts aus." },
  "maintenance.ended": { label: "Wartung aus", icon: Wrench, tone: "plain", meaning: "Das Wartungsfenster ist vorbei." },
  "test.ping": { label: "Test", icon: Bell, tone: "plain", meaning: "Ein Test-Ereignis, von Hand ausgelöst." },
}

const fallback = { label: "Ereignis", icon: Bell, tone: "plain" as const, meaning: "" }

function dayLabel(iso: string) {
  const d = new Date(iso)
  const today = new Date()
  const yst = new Date(Date.now() - 86_400_000)
  const same = (a: Date, b: Date) => a.toDateString() === b.toDateString()
  if (same(d, today)) return "Heute"
  if (same(d, yst)) return "Gestern"
  return d.toLocaleDateString("de-DE", { weekday: "short", day: "2-digit", month: "2-digit", year: "numeric" })
}

/** Events as a day-by-day feed: what happened, where, when. */
export function EventList({ events, showWhere = true, emptyTitle = "Alles ruhig", emptyText = "Kein Ereignis im gewählten Zeitraum.", footer }: {
  events: EventRow[]; showWhere?: boolean; emptyTitle?: string; emptyText?: React.ReactNode; footer?: React.ReactNode
}) {
  const navigate = useNavigate()
  if (events.length === 0) {
    return <Empty className="border"><EmptyHeader><EmptyMedia variant="icon"><Bell /></EmptyMedia><EmptyTitle>{emptyTitle}</EmptyTitle><EmptyDescription>{emptyText}</EmptyDescription></EmptyHeader></Empty>
  }
  const go = (e: EventRow) => {
    if (e.host_id) navigate(`/hosts/${e.host_id}`)
    else if (e.device_id) navigate(`/devices/${e.device_id}`)
    else if (e.site_id) navigate(`/sites/${e.site_id}`)
  }
  let lastDay = ""
  return (
    <div className="flex flex-col gap-2">
      <ul className="divide-y rounded-xl border">
        {events.map((e) => {
          const k = eventKinds[e.type] ?? fallback
          const day = dayLabel(e.occurred_at)
          const head = day !== lastDay
          lastDay = day
          const Icon = k.icon
          return (
            <li key={e.event_id}>
              {head && <div className="bg-muted/50 px-3 py-1 text-xs font-medium text-muted-foreground">{day}</div>}
              <button type="button" onClick={() => go(e)} className="flex w-full items-start gap-3 px-3 py-2.5 text-left transition-colors hover:bg-muted/40">
                <Icon className={cn("mt-0.5 size-4 shrink-0", k.tone === "bad" ? "text-destructive" : k.tone === "good" ? "text-primary" : "text-muted-foreground")} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-x-2">
                    <span className="font-medium">{e.Title || k.label}</span>
                    <span className="text-xs text-muted-foreground">{k.label}</span>
                  </div>
                  <div className="truncate text-xs text-muted-foreground">
                    {showWhere && (e.TenantName || e.SiteName) && <>{e.TenantName}{e.SiteName ? ` · ${e.SiteName}` : ""}{e.Info ? " · " : ""}</>}
                    {e.Info}
                  </div>
                </div>
                <span className="shrink-0 text-xs text-muted-foreground" title={fmtDateTime(e.occurred_at)}><Ago t={e.occurred_at} /></span>
              </button>
            </li>
          )
        })}
      </ul>
      {footer && <div className="text-sm text-muted-foreground">{footer}</div>}
    </div>
  )
}

/** What the kinds mean — shown once on the events page, not on every card. */
export function EventLegend() {
  return (
    <div className="grid gap-x-6 gap-y-2 rounded-md border bg-muted/30 p-3 text-sm @2xl/main:grid-cols-2">
      {Object.entries(eventKinds).filter(([t]) => t !== "test.ping" && !t.startsWith("maintenance")).map(([t, k]) => {
        const Icon = k.icon
        return (
          <div key={t} className="flex items-start gap-2">
            <Icon className={cn("mt-0.5 size-4 shrink-0", k.tone === "bad" ? "text-destructive" : k.tone === "good" ? "text-primary" : "text-muted-foreground")} />
            <div><span className="font-medium">{k.label}</span> <span className="text-muted-foreground">{k.meaning}</span></div>
          </div>
        )
      })}
    </div>
  )
}
