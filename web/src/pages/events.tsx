import { useState } from "react"
import { useSearchParams } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { HelpCircle } from "lucide-react"
import { PageHeader } from "@/components/page-header"
import { EventLegend, EventList, eventKinds } from "@/components/event-list"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type EventRow, type TenantRow } from "@/lib/api"

export default function EventsPage() {
  const [params, setParams] = useSearchParams()
  const range = params.get("range") || "24h"
  const tenant = params.get("tenant") || ""
  const site = params.get("site") || ""
  const type = params.get("type") || ""
  const [filter, setFilter] = useState("")
  const [help, setHelp] = useState(false)
  const q = useQuery({ queryKey: ["events", range, tenant, site, type], queryFn: () => get<{ range: string; events: EventRow[] | null }>("/api/events", { range, tenant, site, type }) })
  const tenants = useQuery({ queryKey: ["tenants"], queryFn: () => get<TenantRow[]>("/api/tenants") })
  const set = (k: string, v: string) => { const p = new URLSearchParams(params); if (v) p.set(k, v); else p.delete(k); setParams(p, { replace: true }) }
  const all = q.data?.events ?? []
  const rows = all.filter((e) => !filter || `${e.Title} ${e.Info} ${e.TenantName} ${e.SiteName}`.toLowerCase().includes(filter.toLowerCase()))
  const red = all.filter((e) => e.Class === "down").length

  return (
    <>
      <PageHeader
        crumbs={[{ label: "Ereignisse" }]}
        title="Ereignisse"
        sub={<>Wann sich etwas geändert hat: ausgefallen, wieder da, neu im Netz, Sicherheitswarnung. Keine Logs, nur Wechsel. {all.length} im Zeitraum{red ? <>, davon <span className="text-destructive">{red} rot</span></> : ""}.</>}
        actions={<Button variant="outline" size="sm" onClick={() => setHelp((h) => !h)}><HelpCircle />Was bedeuten die?</Button>}
      />
      {help && <EventLegend />}

      <div className="flex flex-wrap items-center gap-2">
        <ToggleGroup type="single" value={range} onValueChange={(v) => v && set("range", v)} variant="outline" size="sm">
          <ToggleGroupItem value="24h">24 h</ToggleGroupItem><ToggleGroupItem value="7d">7 Tage</ToggleGroupItem><ToggleGroupItem value="30d">30 Tage</ToggleGroupItem>
        </ToggleGroup>
        <Select value={tenant || "__all"} onValueChange={(v) => set("tenant", v === "__all" ? "" : v)}>
          <SelectTrigger size="sm" className="w-full sm:w-56"><SelectValue placeholder="Alle Kunden" /></SelectTrigger>
          <SelectContent><SelectItem value="__all">Alle Kunden</SelectItem>{(tenants.data ?? []).map((t) => <SelectItem key={t.ID} value={t.ID}>{t.Name}</SelectItem>)}</SelectContent>
        </Select>
        <Select value={type || "__all"} onValueChange={(v) => set("type", v === "__all" ? "" : v)}>
          <SelectTrigger size="sm" className="w-full sm:w-52"><SelectValue placeholder="Alle Arten" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="__all">Alle Arten</SelectItem>
            {Object.entries(eventKinds).map(([t, k]) => <SelectItem key={t} value={t}>{k.label}</SelectItem>)}
          </SelectContent>
        </Select>
        <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Gerät, Kunde, Standort" className="h-8 w-full sm:w-56" />
      </div>

      {q.isLoading ? <Skeleton className="h-96" /> : <EventList events={rows} emptyText={all.length ? "Kein Ereignis passt zum Filter." : "Kein Ereignis im gewählten Zeitraum. Das ist der Normalfall: Ereignisse entstehen nur, wenn sich ein Zustand ändert."} />}
    </>
  )
}
