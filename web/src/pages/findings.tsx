import { useState } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { PageHeader } from "@/components/page-header"
import { StatCard, StatGrid } from "@/components/stat-card"
import { FindingsList } from "@/components/findings-list"
import { Input } from "@/components/ui/input"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type FindingsData } from "@/lib/api"

// Prevention: what the rules found across every customer, worst first.
export default function FindingsPage() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["findings"], queryFn: () => get<FindingsData>("/api/findings"), refetchInterval: 60_000 })
  const [sev, setSev] = useState("all")
  const [filter, setFilter] = useState("")
  const d = q.data
  const refresh = () => { qc.invalidateQueries({ queryKey: ["findings"] }); qc.invalidateQueries({ queryKey: ["me"] }) }
  const items = (d?.open ?? []).filter((f) => (sev === "all" || f.severity === sev) && (!filter || `${f.title} ${f.device} ${f.tenant} ${f.site} ${f.rule}`.toLowerCase().includes(filter.toLowerCase())))
  const open = d?.open ?? []
  const unacked = open.filter((f) => !f.ack)
  return (
    <>
      <PageHeader crumbs={[{ label: "Prävention" }]} title="Prävention" sub="Regeln über das, was die Konnektoren lesen: Verwaltung von außen, Lizenzen, Tunnel, Ressourcen. Ein Finding bleibt offen, bis die Ursache weg ist." />
      {d ? (
        <StatGrid>
          <StatCard label="Hoch" value={d.counts.high ?? 0} tone={(d.counts.high ?? 0) > 0 ? "bad" : "ok"} line1={(d.counts.high ?? 0) ? "Jetzt ansehen" : "Nichts Dringendes"} line2="Verwaltung von außen, abgelaufene Lizenzen, HA ohne Partner" />
          <StatCard label="Mittel" value={d.counts.medium ?? 0} line1="Bei Gelegenheit beheben" line2="Tunnel unten, Klartext-Verwaltung, Lizenz läuft ab, Ressourcen" />
          <StatCard label="Niedrig" value={d.counts.low ?? 0} line1="Hygiene" line2="Zertifikat nicht festgenagelt, lange Timeouts" />
          <StatCard label="Quittiert" value={open.length - unacked.length} line1={`${unacked.length} offen und unquittiert`} line2="Quittiert = gesehen, bleibt sichtbar bis behoben" />
        </StatGrid>
      ) : <Skeleton className="h-32" />}
      <div className="flex flex-wrap items-center gap-2">
        <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Gerät, Kunde oder Regel" className="w-72" />
        <ToggleGroup type="single" value={sev} onValueChange={(v) => v && setSev(v)} variant="outline" size="sm">
          <ToggleGroupItem value="all">alle</ToggleGroupItem><ToggleGroupItem value="high">hoch</ToggleGroupItem><ToggleGroupItem value="medium">mittel</ToggleGroupItem><ToggleGroupItem value="low">niedrig</ToggleGroupItem>
        </ToggleGroup>
        {d && <span className="text-sm text-muted-foreground">{items.length} von {open.length}</span>}
      </div>
      {d ? <FindingsList items={items} onChanged={refresh} emptyText={open.length ? "Kein Finding passt zum Filter." : "Die Regeln haben auf keinem Gerät etwas zu beanstanden. Sobald ein Konnektor liest, prüfen sie jede Lesung."} /> : <Skeleton className="h-48" />}
    </>
  )
}
