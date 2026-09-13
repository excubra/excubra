import { useMemo, useState } from "react"
import { Link, useNavigate } from "react-router"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { AlertTriangle, CheckCircle2, Plus } from "lucide-react"
import { PageHeader } from "@/components/page-header"
import { EventList } from "@/components/event-list"
import { StatCard, StatGrid } from "@/components/stat-card"
import { AvailabilityChart } from "@/components/availability-chart"
import { DataTable } from "@/components/data-table"
import { StateBadge } from "@/components/status"
import { Ago } from "@/components/clock"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type Me, type Overview, type SiteCard } from "@/lib/api"
import { fmtTime, n } from "@/lib/format"
import { AttentionCard } from "@/components/attention-list"
import { SiteMap, type MapPoint } from "@/components/site-map"
import { Card } from "@/components/ui/card"

// The same four states the badges use, so a marker and a badge never disagree.
const mapTone = (c: SiteCard): MapPoint["tone"] => (!c.HasBox ? "none" : !c.Online ? "silent" : c.Down > 0 ? "bad" : "ok")

export default function OverviewPage() {
  const [range, setRange] = useState("24h")
  const navigate = useNavigate()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["overview", range], queryFn: () => get<Overview>("/api/overview", { range }), refetchInterval: 30_000 })
  const d = q.data
  const attention = d?.attention ?? []
  const open = attention.filter((a) => !a.ack)
  const refresh = () => { qc.invalidateQueries({ queryKey: ["overview"] }); qc.invalidateQueries({ queryKey: ["me"] }) }
  const me = useQuery({ queryKey: ["me"], queryFn: () => get<Me>("/api/me") })
  const [picked, setPicked] = useState<string>()
  const cards = useMemo(() => d?.Cards ?? [], [d])
  const points: MapPoint[] = useMemo(() => cards
    .filter((c) => c.Site.Located && typeof c.Site.Lat === "number" && typeof c.Site.Lon === "number")
    .map((c) => ({ id: c.Site.ID, name: c.Site.Name, tenant: c.Tenant.Name, lat: c.Site.Lat as number, lon: c.Site.Lon as number, tone: mapTone(c) })), [cards])
  const chosen = picked ? cards.find((c) => c.Site.ID === picked) : undefined

  const siteCols: ColumnDef<SiteCard, unknown>[] = [
    { id: "site", header: "Standort", accessorFn: (r) => r.Site.Name, cell: ({ row }) => <div><div className="font-medium">{row.original.Site.Name}</div><div className="text-xs text-muted-foreground">{row.original.Tenant.Name}</div></div> },
    { id: "box", header: "Box", accessorFn: (r) => r.Box?.Name ?? "", cell: ({ row }) => row.original.HasBox ? <div><span className="font-mono text-xs">{row.original.Box!.Name || row.original.Box!.ID}</span><div className="text-xs text-muted-foreground">Heartbeat <Ago t={row.original.Box!.State.LastHeartbeat} /></div></div> : <Badge variant="secondary">keine</Badge> },
    { id: "state", header: "Zustand", accessorFn: (r) => r.Class, cell: ({ row }) => { const r = row.original; return !r.HasBox ? <Badge variant="secondary">ohne Box</Badge> : !r.Online ? <StateBadge cls="silent" label="Box schweigt" /> : r.Down ? <StateBadge cls="down" label={`${r.Down} ausgefallen`} /> : <StateBadge cls="ok" label="online" /> } },
    { id: "mon", header: "Beobachtet", accessorFn: (r) => r.Monitored, meta: { align: "right" } },
    { id: "up", header: "Erreichbar", accessorFn: (r) => r.Up, meta: { align: "right" } },
    { id: "down", header: "Ausgefallen", accessorFn: (r) => r.Down, meta: { align: "right" }, cell: ({ getValue }) => <span className={Number(getValue()) > 0 ? "font-semibold text-destructive" : ""}>{String(getValue())}</span> },
    { id: "devices", header: "Geräte", accessorFn: (r) => r.Devices, meta: { align: "right" } },
    { id: "last", header: "Zuletzt", accessorFn: (r) => r.Last?.occurred_at ?? "", cell: ({ row }) => row.original.Last ? <span className="text-muted-foreground"><span className="font-mono text-xs">{fmtTime(row.original.Last.occurred_at)}</span> {row.original.Last.Title}</span> : <span className="text-muted-foreground">–</span> },
  ]

  return (
    <>
      <PageHeader crumbs={[{ label: "Übersicht" }]} title="Übersicht" sub="Was jetzt einen Menschen braucht, dann alles andere. Aktualisiert sich alle 30 Sekunden."
        actions={<Button asChild variant="outline" size="sm"><Link to="/tenants"><Plus />Kunde anlegen</Link></Button>} />

      {!d ? <StatGrid>{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-36" />)}</StatGrid> : (
        <StatGrid>
          <StatCard label="Braucht Aufmerksamkeit" value={open.length} tone={open.length ? "bad" : "ok"} badge={open.length ? <Badge variant="outline" className="border-destructive/40 text-destructive"><AlertTriangle />offen</Badge> : <Badge variant="outline" className="border-primary/40 text-primary"><CheckCircle2 />ruhig</Badge>}
            line1={open.length ? `${open.filter((a) => a.kind === "host_down").length} Hosts ausgefallen, ${open.filter((a) => a.kind === "box_silent").length} Boxen still` : attention.length ? `Keine offen, ${attention.length} quittiert` : "Keine Störung offen"} line2={`${d.SitesOnline} von ${d.SitesWithBox} Standorten mit Box online`} />
          <StatCard label="Beobachtet" value={n(d.Total)} badge={<Badge variant="outline">{n(d.Devices)} Geräte</Badge>} line1={`${d.Up} erreichbar${d.Maint ? ` · ${d.Maint} in Wartung` : ""}`} line2="Prüfung jede Minute von der Box im LAN" />
          <StatCard label="Kunden · Standorte" value={<>{d.Cards ? new Set(d.Cards.map((c) => c.Tenant.ID)).size : 0}<span className="ml-2 text-base font-medium text-muted-foreground">· {d.SitesTotal}</span></>} badge={<Badge variant="outline">{d.Boxes} Boxen</Badge>} line1={d.Unassigned?.length ? `${d.Unassigned.length} Box ohne Standort` : "Alle Boxen zugeordnet"} line2={d.SitesTotal > d.SitesWithBox ? `${d.SitesTotal - d.SitesWithBox} Standorte ohne Box` : "Jeder Standort hat eine Box"} to="/tenants" />
          <StatCard label="Ereignisse 24 h" value={n(d.Events24h)} badge={d.Recent?.[0] ? <Badge variant="outline" className="font-mono">{fmtTime(d.Recent[0].occurred_at)}</Badge> : undefined} line1={d.Recent?.[0]?.Title ?? "Alles ruhig"} line2="Nur Zustandswechsel, keine Logs" to="/events" />
        </StatGrid>
      )}

      {d && <AttentionCard items={attention} onChanged={refresh} />}

      {/* Where the fleet is, next to what it is doing. Only when somebody has
          entered an address; an empty map is a hole in the page, not a feature. */}
      {points.length > 0 && (
        <Card className="gap-0 py-0">
          <div className="relative">
            <SiteMap
              points={points}
              tiles={me.data?.map?.tiles}
              attribution={me.data?.map?.attribution}
              selected={picked}
              onSelect={setPicked}
              className="h-72 rounded-xl border-0"
            />
            {chosen && (
              <div className="pointer-events-none absolute inset-x-3 bottom-8 flex sm:inset-x-auto sm:left-3 sm:max-w-xs">
                <button type="button" onClick={() => navigate(`/sites/${chosen.Site.ID}`)}
                  className="pointer-events-auto w-full rounded-lg border bg-background/95 p-3 text-left shadow-lg backdrop-blur transition-colors hover:bg-muted/60">
                  <span className="block truncate font-medium">{chosen.Site.Name}</span>
                  <span className="block truncate text-xs text-muted-foreground">{chosen.Tenant.Name}</span>
                  <span className="mt-1 block text-xs text-muted-foreground">
                    {chosen.Down ? <span className="text-destructive">{chosen.Down} ausgefallen</span> : !chosen.Online ? <span className="text-destructive">Box schweigt</span> : "ruhig"}
                    {" · "}{chosen.Monitored} beobachtet
                  </span>
                </button>
              </div>
            )}
          </div>
        </Card>
      )}

      {d ? <AvailabilityChart chart={d.Chart} range={range} onRange={setRange} /> : <Skeleton className="h-[340px]" />}

      {d && (
        <Tabs defaultValue="sites">
          <TabsList>
            <TabsTrigger value="sites">Standorte <Badge variant="secondary" className="ml-1">{d.SitesTotal}</Badge></TabsTrigger>
            <TabsTrigger value="events">Ereignisse <Badge variant="secondary" className="ml-1">{d.Events24h}</Badge></TabsTrigger>
          </TabsList>
          <TabsContent value="sites" className="mt-3">
            <DataTable columns={siteCols} data={d.Cards ?? []} search={(r) => `${r.Site.Name} ${r.Tenant.Name} ${r.Box?.Name ?? ""}`} searchPlaceholder="Standort oder Kunde" onRowClick={(r) => navigate(`/sites/${r.Site.ID}`)} rowClass={(r) => r.Down ? "border-l-2 border-l-destructive" : ""} initialSort={[{ id: "down", desc: true }]} emptyTitle="Noch kein Standort" emptyText={<span>Unter <Link className="underline" to="/tenants">Kunden</Link> den ersten anlegen.</span>} footer={<Link className="underline" to="/sites">Alle Standorte</Link>} />
          </TabsContent>
          <TabsContent value="events" className="mt-3">
            <EventList events={d.Recent ?? []} emptyText="Keine Ereignisse in den letzten 24 Stunden." footer={<Link className="underline" to="/events">Alle Ereignisse</Link>} />
          </TabsContent>
        </Tabs>
      )}
    </>
  )
}
