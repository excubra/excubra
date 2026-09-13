import { useMemo, useState } from "react"
import { Link, useNavigate, useParams, useSearchParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { LayoutGrid, List, Radar, Wrench, EyeOff, Eye } from "lucide-react"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { EventList } from "@/components/event-list"
import { StatCard, StatGrid } from "@/components/stat-card"
import { AvailabilityChart } from "@/components/availability-chart"
import { DataTable } from "@/components/data-table"
import { StateBadge, LiveDot } from "@/components/status"
import { Ago } from "@/components/clock"
import { DeviceMark, KindIcon } from "@/components/kind-icon"
import { DeviceCardView } from "@/components/device-card"
import { BoxTech } from "@/components/box-tech"
import { TaskMenu } from "@/components/task-menu"
import { RemoteAccessCard } from "@/components/remote-access"
import { ScanCard } from "@/components/scan-card"
import { CanaryCard } from "@/components/canary-card"
import { DNSCard } from "@/components/dns-card"
import { AICard } from "@/components/ai-card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/checkbox"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Skeleton } from "@/components/ui/skeleton"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { SiteLocationCard } from "@/components/site-location-card"
import { ConnectIP } from "@/components/connect"
import { PingCell } from "@/components/ping-bar"
import { SuggestWatchButton } from "@/components/suggest-watch"
import { get, post, type DeviceCard, type HostCard, type Me, type SiteData } from "@/lib/api"
import { fmtShort, fmtTime, pct } from "@/lib/format"

export default function SitePage() {
  const { id = "" } = useParams()
  const [params, setParams] = useSearchParams()
  const tab = params.get("tab") || "netz"
  const range = params.get("range") || "24h"
  const navigate = useNavigate()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["site", id, range], queryFn: () => get<SiteData>(`/api/sites/${id}`, { range }) })
  const me = useQuery({ queryKey: ["me"], queryFn: () => get<Me>("/api/me") })
  const [view, setView] = useState<"table" | "cards">(() => (localStorage.getItem("ex0.devview") as "table" | "cards") || "table")
  const [kind, setKind] = useState("all")
  const [selected, setSelected] = useState<DeviceCard[]>([])
  const d = q.data
  const refresh = () => { qc.invalidateQueries({ queryKey: ["site", id] }); qc.invalidateQueries({ queryKey: ["me"] }) }
  const act = useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post(path, form),
    onSuccess: (r) => { toast.success(r.message); refresh() },
    onError: (e) => toast.error(e.message),
  })
  const bulk = async (fn: (dev: DeviceCard) => Promise<unknown> | null) => {
    const jobs = selected.map(fn).filter(Boolean)
    const res = await Promise.allSettled(jobs as Promise<unknown>[])
    const failed = res.filter((r) => r.status === "rejected").length
    toast[failed ? "error" : "success"](failed ? `${failed} von ${jobs.length} fehlgeschlagen` : `${jobs.length} Geräte geändert`)
    setSelected([]); refresh()
  }
  const devices = useMemo(() => (d?.Devices ?? []).filter((x) => kind === "all" || (kind === "mon" ? x.Monitored : x.Kind === kind)), [d, kind])
  const setTab = (t: string) => { const p = new URLSearchParams(params); p.set("tab", t); setParams(p, { replace: true }) }
  const setRange = (r: string) => { const p = new URLSearchParams(params); p.set("range", r); setParams(p, { replace: true }) }

  const devCols: ColumnDef<DeviceCard, unknown>[] = [
    { id: "sel", enableSorting: false, header: ({ table }) => <Checkbox checked={table.getIsAllPageRowsSelected() || (table.getIsSomePageRowsSelected() && "indeterminate")} onCheckedChange={(v) => table.toggleAllPageRowsSelected(!!v)} aria-label="Alle" />, cell: ({ row }) => <Checkbox checked={row.getIsSelected()} onCheckedChange={(v) => row.toggleSelected(!!v)} aria-label="Auswählen" disabled={row.original.IsBox} /> },
    { id: "kind", header: "Art", accessorFn: (r) => `${r.KindLabel} ${r.Vendor}`, cell: ({ row }) => <span className="flex items-center gap-2 text-muted-foreground"><DeviceMark kind={row.original.Kind} vendor={row.original.Vendor} active={row.original.Monitored} />{row.original.KindLabel}</span> },
    { id: "name", header: "Gerät", accessorFn: (r) => r.Name, cell: ({ row }) => <div><Link to={`/devices/${row.original.ID}`} className="font-medium hover:underline">{row.original.Name}</Link>{row.original.Hostname && row.original.Hostname !== row.original.Name && <div className="text-xs text-muted-foreground">{row.original.Hostname}</div>}</div> },
    { id: "ip", header: "Adresse", accessorFn: (r) => r.IP, cell: ({ row }) => <ConnectIP ip={row.original.IP} ways={row.original.Ways} sub={row.original.MAC} className="text-sm" /> },
    { id: "vendor", header: "Hersteller", accessorFn: (r) => r.Vendor, cell: ({ getValue }) => <span className="text-muted-foreground">{String(getValue() || "unbekannt")}</span> },
    { id: "ping", header: "Erreichbarkeit", enableSorting: true, accessorFn: (r) => (r.Ping ? r.Ping.pct : -1), meta: { className: "hidden @3xl/main:table-cell" }, cell: ({ row }) => <PingCell ping={row.original.Ping} /> },
    { id: "state", header: "Zustand", accessorFn: (r) => (r.Monitored ? r.StateClass : "zz"), cell: ({ row }) => { const r = row.original; if (r.IsBox) return <Badge variant="secondary">diese Box</Badge>; if (r.IsUplink) return <span className="flex gap-1"><StateBadge cls={r.StateClass} /><Badge variant="outline" className="border-primary/40 text-primary">Uplink</Badge></span>; return r.Monitored ? <StateBadge cls={r.StateClass} /> : <span className="text-muted-foreground">nicht beobachtet</span> } },
    { id: "seen", header: "Gesehen", accessorFn: (r) => r.LastSeen, cell: ({ row }) => <span className={"text-xs " + (row.original.GoneAt ? "text-destructive" : "text-muted-foreground")}>{row.original.GoneAt ? <>weg seit <Ago t={row.original.GoneAt} /></> : <>seit {fmtShort(row.original.FirstSeen)}</>}</span> },
    { id: "watch", header: "Beobachten", enableSorting: false, cell: ({ row }) => { const r = row.original; return r.IsBox ? null : <Switch checked={r.Monitored} disabled={!r.IP || act.isPending} aria-label={`${r.Name} beobachten`} onCheckedChange={(on) => act.mutate({ path: on ? `/api/devices/${r.ID}/watch` : `/api/hosts/${r.HostID}/unwatch` })} /> } },
  ]
  const hostCols: ColumnDef<HostCard, unknown>[] = [
    { id: "name", header: "Host", accessorFn: (r) => r.Name, cell: ({ row }) => <div><Link to={`/hosts/${row.original.ID}`} className="font-medium hover:underline">{row.original.Name}</Link>{row.original.Vendor && <div className="text-xs text-muted-foreground">{row.original.Vendor}</div>}</div> },
    { id: "ip", header: "Adresse", accessorFn: (r) => r.Address, cell: ({ getValue }) => <span className="font-mono text-sm">{String(getValue())}</span> },
    { id: "state", header: "Zustand", accessorFn: (r) => r.StateClass, cell: ({ row }) => <StateBadge cls={row.original.StateClass} label={row.original.StateLabel} /> },
    { id: "since", header: "Seit", accessorFn: (r) => r.State.Since, cell: ({ row }) => <span className="text-muted-foreground"><Ago t={row.original.State.Since} /></span> },
    { id: "avail", header: "Verfügbarkeit 24 h", accessorFn: (r) => r.Avail.Pct, cell: ({ row }) => <span className="flex items-center gap-2"><span className={"font-mono " + (row.original.Avail.Pct < 90 ? "text-destructive" : "")}>{pct(row.original.Avail.Pct)} %</span><span className="inline-flex h-3.5 w-28 gap-px">{row.original.Avail.Hours.map((h, i) => <i key={i} title={`${h.Label}: ${h.Pct < 0 ? "keine Daten" : pct(h.Pct) + " %"}`} className={"flex-1 rounded-[1px] " + (h.Class === "ok" ? "bg-primary" : h.Class === "down" ? "bg-destructive" : h.Class === "warn" ? "bg-muted-foreground" : "bg-muted")} />)}</span></span> },
    { id: "check", header: "Prüfung", accessorFn: (r) => r.Checks, cell: ({ getValue }) => <span className="text-muted-foreground">{String(getValue())}</span> },
    { id: "uplink", header: "Uplink", accessorFn: (r) => (r.IsUplink ? "1" : r.UplinkName), cell: ({ row }) => row.original.IsUplink ? <Badge variant="outline" className="border-primary/40 text-primary">Uplink</Badge> : row.original.UplinkName ? <span className="text-muted-foreground">hinter {row.original.UplinkName}</span> : <span className="text-muted-foreground">–</span> },
    { id: "act", header: "", enableSorting: false, cell: ({ row }) => <Button variant="ghost" size="xs" onClick={() => act.mutate({ path: `/api/hosts/${row.original.ID}/uplink` })}>{row.original.IsUplink ? "Uplink aufheben" : "Als Uplink"}</Button> },
  ]

  if (!d) return <div className="flex flex-col gap-6"><Skeleton className="h-16" /><StatGrid>{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-36" />)}</StatGrid><Skeleton className="h-96" /></div>
  const online = !!d.Box && d.Online
  return (
    <>
      <PageHeader crumbs={[{ label: "Kunden", to: "/tenants" }, { label: d.Tenant.Name, to: `/tenants/${d.Tenant.ID}` }, { label: d.Site.Name }]}
        title={<>{d.Site.Name}{d.Box ? <span className="flex items-center gap-2 text-sm font-medium"><LiveDot ok={online} />{online ? "online" : "Box schweigt"}</span> : <Badge variant="secondary">keine Box</Badge>}</>}
        sub={<span className="font-mono">{d.Site.ID}</span>}
        actions={<>{d.Box && <TaskMenu path={`/api/sites/${id}/tasks`} onDone={refresh} />}<Button asChild variant="outline" size="sm"><Link to={`/maintenance?site=${d.Site.ID}`}><Wrench />Wartung planen</Link></Button></>} />

      <StatGrid>
        <StatCard label="Box" value={d.Box ? (online ? "online" : "schweigt") : "keine"} tone={d.Box ? (online ? "ok" : "bad") : undefined} badge={d.Box ? <Badge variant="outline" className="font-mono">{d.Box.Name || d.Box.ID}</Badge> : undefined}
          line1={d.Box ? <>Heartbeat <Ago t={d.Box.State.LastHeartbeat} /></> : "Erst eine Box zuordnen"} line2={d.Box ? `Agent ${d.Box.AgentVersion || "–"} · ${d.Box.NetbirdStatus === "connected" ? "NetBird verbunden" : "kein Overlay"}` : "Ohne Box kein Inventar"} />
        <StatCard label="Geräte im Netz" value={d.Devices?.length ?? 0} badge={d.Box ? <Badge variant="outline">{d.Box.DiscoveryMode === "sweep" ? "Sweep 15 min" : "passiv"}</Badge> : undefined}
          line1={(d.Kinds ?? []).slice(0, 3).map((k) => `${k.N} ${k.Label}`).join(" · ") || "noch nichts gesehen"} line2={`${d.Monitored} beobachtet${d.Ignored ? ` · ${d.Ignored} ignoriert` : ""}`} />
        <StatCard label="Ausgefallen" value={d.Down} tone={d.Down ? "bad" : undefined} badge={d.Down ? <StateBadge cls="down" label="rot" /> : d.Monitored ? <StateBadge cls="ok" label="alles ok" /> : undefined}
          line1={`${d.Up} von ${d.Monitored} erreichbar`} line2={d.Unknown ? `${d.Unknown} noch ohne Ergebnis` : d.Maint ? `${d.Maint} in Wartung` : "Prüfung jede Minute per Ping"} />
        <StatCard label="Ereignisse 24 h" value={d.Events?.length ?? 0} badge={d.Red ? <StateBadge cls="down" label={`${d.Red} rot`} /> : <Badge variant="outline">ruhig</Badge>}
          line1={d.Events?.[0]?.Title ?? "Kein Ereignis"} line2={d.Events?.[0] ? `zuletzt ${fmtTime(d.Events[0].occurred_at)}` : "Nur Zustandswechsel"} />
      </StatGrid>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="netz">Netz <Badge variant="secondary" className="ml-1">{d.Devices?.length ?? 0}</Badge></TabsTrigger>
          <TabsTrigger value="ueberwachung">Überwachung <Badge variant={d.Down ? "destructive" : "secondary"} className="ml-1">{d.Monitored}</Badge></TabsTrigger>
          <TabsTrigger value="ereignisse">Ereignisse <Badge variant="secondary" className="ml-1">{d.Events?.length ?? 0}</Badge></TabsTrigger>
          <TabsTrigger value="technik">Technik</TabsTrigger>
          <TabsTrigger value="ki">KI</TabsTrigger>
        </TabsList>

        <TabsContent value="ki" className="mt-4">
          <AICard siteId={id} tenantId={d.Tenant.ID} />
        </TabsContent>

        <TabsContent value="netz" className="mt-4 flex flex-col gap-4">
          {!d.Box && <Alert><Radar /><AlertTitle>Keine Box an diesem Standort</AlertTitle><AlertDescription>Ohne Box kein Inventar und keine Prüfungen. <Link className="underline" to="/boxes">Zu den Boxen</Link></AlertDescription></Alert>}
          <div className="flex flex-wrap items-center gap-2">
            <ToggleGroup type="single" value={kind} onValueChange={(v) => v && setKind(v)} variant="outline" size="sm" className="flex-wrap">
              <ToggleGroupItem value="all">Alle <span className="ml-1 text-muted-foreground">{d.Devices?.length ?? 0}</span></ToggleGroupItem>
              {(d.Kinds ?? []).map((k) => <ToggleGroupItem key={k.Key} value={k.Key}><KindIcon kind={k.Key} className="size-3.5" />{k.Label} <span className="ml-1 text-muted-foreground">{k.N}</span></ToggleGroupItem>)}
              <ToggleGroupItem value="mon">Beobachtet <span className="ml-1 text-muted-foreground">{d.Monitored}</span></ToggleGroupItem>
            </ToggleGroup>
            <div className="ml-auto flex items-center gap-2">
              {selected.length > 0 && view === "table" && (
                <>
                  <span className="text-sm text-muted-foreground">{selected.length} ausgewählt</span>
                  <Button size="sm" variant="outline" onClick={() => bulk((x) => (!x.Monitored && x.IP ? post(`/api/devices/${x.ID}/watch`) : null))}><Eye />Beobachten</Button>
                  <Button size="sm" variant="outline" onClick={() => bulk((x) => (x.Monitored ? post(`/api/hosts/${x.HostID}/unwatch`) : null))}><EyeOff />Nicht mehr</Button>
                  <Button size="sm" variant="ghost" onClick={() => bulk((x) => post(`/api/devices/${x.ID}/ignore`, { ignored: x.Ignored ? "0" : "1" }))}>Ignorieren an/aus</Button>
                </>
              )}
              {selected.length === 0 && <SuggestWatchButton siteId={id} onDone={refresh} />}
              <ToggleGroup type="single" value={view} onValueChange={(v) => { if (v) { setView(v as "table" | "cards"); localStorage.setItem("ex0.devview", v) } }} variant="outline" size="sm">
                <ToggleGroupItem value="table" aria-label="Tabelle"><List /></ToggleGroupItem>
                <ToggleGroupItem value="cards" aria-label="Karten"><LayoutGrid /></ToggleGroupItem>
              </ToggleGroup>
            </div>
          </div>
          {view === "table" ? (
            <DataTable columns={devCols} data={devices} search={(r) => r.Text} searchPlaceholder="Name, IP, MAC, Hersteller" selection onSelectionChange={setSelected} pageSize={50} onRowClick={(r) => navigate(`/devices/${r.ID}`)} initialSort={[{ id: "state", desc: false }]} rowClass={(r) => (r.Ignored ? "opacity-50" : "") + (r.Monitored && r.StateClass === "down" ? " border-l-2 border-l-destructive" : "")} emptyTitle="Noch keine Geräte gesehen" emptyText="Die Box meldet Geräte mit jedem Heartbeat; der erste Sweep läuft eine halbe Minute nach dem Start." />
          ) : (
            <DeviceCardView devices={devices} onToggle={(r, on) => act.mutate({ path: on ? `/api/devices/${r.ID}/watch` : `/api/hosts/${r.HostID}/unwatch` })} busy={act.isPending} onOpen={(r) => navigate(`/devices/${r.ID}`)} />
          )}
        </TabsContent>

        <TabsContent value="ueberwachung" className="mt-4 flex flex-col gap-4">
          <AvailabilityChart chart={d.Chart} range={range} onRange={setRange} />
          <DataTable columns={hostCols} data={d.Hosts ?? []} search={(r) => `${r.Name} ${r.Address} ${r.Vendor}`} initialSort={[{ id: "state", desc: true }]} rowClass={(r) => r.StateClass === "down" ? "border-l-2 border-l-destructive" : ""} emptyTitle="Noch nichts beobachtet" emptyText="Im Reiter „Netz“ Geräte einschalten, dann prüft die Box sie jede Minute." footer={<span className="text-xs">3 verpasste Prüfungen sind rot, 2 Erfolge wieder grün · Uplink weg unterdrückt alles dahinter · Box still nach 3½ Minuten friert ein</span>} />
        </TabsContent>

        <TabsContent value="ereignisse" className="mt-4">
          <EventList events={d.Events ?? []} showWhere={false} emptyText="Kein Ereignis in den letzten 24 Stunden." footer={<Link className="underline" to={`/events?site=${d.Site.ID}`}>Alle Ereignisse dieses Standorts</Link>} />
        </TabsContent>

        <TabsContent value="technik" className="mt-4 flex flex-col gap-6">
          <section className="flex flex-col gap-3">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Standort</h2>
            <SiteLocationCard site={d.Site} map={me.data?.map} onChanged={refresh} />
          </section>
          <section className="flex flex-col gap-3">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Erkennung</h2>
            <div className="grid gap-4 @5xl/main:grid-cols-2">
              <CanaryCard siteId={id} />
              <DNSCard siteId={id} />
              <div className="@5xl/main:col-span-2"><ScanCard siteId={id} /></div>
            </div>
          </section>
          <section className="flex flex-col gap-3">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Zugang und Box</h2>
            <RemoteAccessCard siteId={id} />
            {d.Box ? <BoxTech box={d.Box} site={d.Site} sites={d.Sites ?? []} tenantNames={d.TenantNames} fingerprint={d.Fingerprint} netbird={d.Netbird} subnets={d.Subnets} onChanged={refresh} /> : (
              <Alert><Radar /><AlertTitle>Keine Box an diesem Standort</AlertTitle><AlertDescription>Unter <Link className="underline" to="/boxes">Boxen</Link> eine enrollte Box diesem Standort zuordnen.</AlertDescription></Alert>
            )}
          </section>
        </TabsContent>
      </Tabs>
      <span className="hidden" onClick={() => navigate("/")} />
    </>
  )
}
