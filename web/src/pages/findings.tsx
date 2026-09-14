import { useMemo, useState } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { ChevronsDownUp, ChevronsUpDown, Search } from "lucide-react"
import { PageHeader } from "@/components/page-header"
import { StatCard, StatGrid } from "@/components/stat-card"
import { FindingsList } from "@/components/findings-list"
import { Group, useGroups } from "@/components/group"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type FindingView, type FindingsData } from "@/lib/api"

// Prevention across every customer. One block per customer so the list stays
// readable at fifty of them; the ones with something urgent are open.
export default function FindingsPage() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["findings"], queryFn: () => get<FindingsData>("/api/findings"), refetchInterval: 60_000 })
  const [sev, setSev] = useState("all")
  const [source, setSource] = useState("all")
  const [filter, setFilter] = useState("")
  const d = q.data
  const refresh = () => { qc.invalidateQueries({ queryKey: ["findings"] }); qc.invalidateQueries({ queryKey: ["me"] }) }

  const open = useMemo(() => d?.open ?? [], [d])
  const sources = useMemo(() => [...new Set(open.map((f) => f.source).filter(Boolean))].sort(), [open])
  const items = useMemo(() => open.filter((f) =>
    (sev === "all" || f.severity === sev) &&
    (source === "all" || f.source === source) &&
    (!filter || `${f.title} ${f.detail} ${f.device} ${f.tenant} ${f.site} ${f.rule}`.toLowerCase().includes(filter.toLowerCase()))
  ), [open, sev, source, filter])

  const groups = useMemo(() => {
    const byTenant = new Map<string, { name: string; items: FindingView[] }>()
    for (const f of items) {
      const g = byTenant.get(f.tenantId) ?? { name: f.tenant || f.tenantId, items: [] }
      g.items.push(f)
      byTenant.set(f.tenantId, g)
    }
    const order = { high: 0, medium: 1, low: 2 }
    return [...byTenant.entries()].map(([id, g]) => {
      const high = g.items.filter((f) => f.severity === "high").length
      const unacked = g.items.filter((f) => !f.ack).length
      return { id, name: g.name, high, unacked, items: [...g.items].sort((a, b) => order[a.severity] - order[b.severity] || a.device.localeCompare(b.device, "de")) }
    }).sort((a, b) => b.high - a.high || b.items.length - a.items.length || a.name.localeCompare(b.name, "de"))
  }, [items])

  const alwaysOpen = filter.trim() || sev !== "all" || source !== "all" ? groups.map((g) => g.id) : groups.filter((g) => g.high > 0).map((g) => g.id)
  const { isOpen, toggle, setAll } = useGroups(alwaysOpen)
  const ids = groups.map((g) => g.id)
  const allOpen = ids.length > 0 && ids.every(isOpen)
  const unacked = open.filter((f) => !f.ack)

  return (
    <>
      <PageHeader
        crumbs={[{ label: "Prävention" }]}
        title="Prävention"
        sub="Was Scan, Live-Erkennung, CVE-Abgleich, Patch-Stand und Konnektoren gefunden haben: offene Türen von außen, Klartext-Dienste, alte Versionen, bekannte Schwachstellen. Ein Finding bleibt offen, bis die Ursache weg ist."
        actions={ids.length > 1 ? <Button variant="outline" size="sm" onClick={() => setAll(!allOpen, ids)}>{allOpen ? <><ChevronsDownUp />Alle zuklappen</> : <><ChevronsUpDown />Alle aufklappen</>}</Button> : undefined}
      />
      {d ? (
        <StatGrid>
          <StatCard label="Hoch" value={d.counts.high ?? 0} tone={(d.counts.high ?? 0) > 0 ? "bad" : "ok"} line1={(d.counts.high ?? 0) ? "Jetzt ansehen" : "Nichts Dringendes"} line2="Von außen erreichbar, aktiv ausgenutzt, Angriff im LAN" />
          <StatCard label="Mittel" value={d.counts.medium ?? 0} line1="Bei Gelegenheit beheben" line2="Klartext-Dienste, Zertifikate, Support endet bald" />
          <StatCard label="Niedrig" value={d.counts.low ?? 0} line1="Hygiene" line2="Zertifikat nicht festgenagelt, lange Timeouts" />
          <StatCard label="Betroffene Kunden" value={new Set(open.map((f) => f.tenantId)).size} line1={`${unacked.length} offen und unquittiert`} line2="Quittiert = gesehen, bleibt sichtbar bis behoben" />
        </StatGrid>
      ) : <Skeleton className="h-32" />}

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Gerät, Kunde, Regel" className="h-8 w-full pl-8" />
        </div>
        <ToggleGroup type="single" value={sev} onValueChange={(v) => v && setSev(v)} variant="outline" size="sm">
          <ToggleGroupItem value="all">alle</ToggleGroupItem><ToggleGroupItem value="high">hoch</ToggleGroupItem><ToggleGroupItem value="medium">mittel</ToggleGroupItem><ToggleGroupItem value="low">niedrig</ToggleGroupItem>
        </ToggleGroup>
        {sources.length > 1 && (
          <Select value={source} onValueChange={setSource}>
            <SelectTrigger size="sm" className="w-full sm:w-48"><SelectValue /></SelectTrigger>
            <SelectContent><SelectItem value="all">Alle Quellen</SelectItem>{sources.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
          </Select>
        )}
        {d && <span className="text-sm text-muted-foreground">{items.length} von {open.length}</span>}
      </div>

      {!d ? <Skeleton className="h-48" /> : groups.length === 0 ? (
        <Empty className="border"><EmptyHeader><EmptyTitle>{open.length ? "Nichts gefunden" : "Nichts offen"}</EmptyTitle>
          <EmptyDescription>{open.length ? "Kein Finding passt zum Filter." : "Die Regeln haben auf keinem Gerät etwas zu beanstanden. Scan, Live-Erkennung und Konnektoren liefern laufend Neues."}</EmptyDescription></EmptyHeader></Empty>
      ) : (
        <div className="flex flex-col gap-3">
          {groups.map((g) => (
            <Group key={g.id} open={isOpen(g.id)} onToggle={() => toggle(g.id)} tone={g.high ? "bad" : "plain"}
              title={g.name}
              meta={<>{g.items.length} Finding{g.items.length === 1 ? "" : "s"}{g.high ? <span className="text-destructive"> · {g.high} hoch</span> : null}{g.unacked !== g.items.length ? ` · ${g.items.length - g.unacked} quittiert` : ""}</>}>
              <div className="p-3">
                <FindingsList items={g.items} onChanged={refresh} />
              </div>
            </Group>
          ))}
        </div>
      )}
    </>
  )
}
