import { Link, useNavigate, useParams, useSearchParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { Bot, FileText, Plug, Radar, ScrollText } from "lucide-react"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { StatCard, StatGrid } from "@/components/stat-card"
import { DataTable } from "@/components/data-table"
import { StateBadge } from "@/components/status"
import { KindIcon } from "@/components/kind-icon"
import { Ago } from "@/components/clock"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { get, post, type DeviceDetail, type EventRow } from "@/lib/api"
import { fmtDateTime, fmtTime, pct } from "@/lib/format"

function Row({ k, children, mono }: { k: string; children: React.ReactNode; mono?: boolean }) {
  return <div className="grid grid-cols-[150px_1fr] gap-3 text-sm"><span className="text-muted-foreground">{k}</span><span className={mono ? "font-mono text-[13px]" : ""}>{children}</span></div>
}

export default function DevicePage() {
  const { id = "" } = useParams()
  const [params, setParams] = useSearchParams()
  const tab = params.get("tab") || "uebersicht"
  const navigate = useNavigate()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["device", id], queryFn: () => get<DeviceDetail>(`/api/devices/${id}`) })
  const act = useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post(path, form),
    onSuccess: (r) => { toast.success(r.message); qc.invalidateQueries({ queryKey: ["device", id] }) },
    onError: (e) => toast.error(e.message),
  })
  const d = q.data
  const evCols: ColumnDef<EventRow, unknown>[] = [
    { id: "t", header: "Zeit", accessorFn: (r) => r.occurred_at, cell: ({ getValue }) => <span className="font-mono text-xs">{fmtDateTime(String(getValue()))}</span> },
    { id: "type", header: "Ereignis", accessorFn: (r) => r.type, cell: ({ row }) => <Badge variant="outline" className={"font-mono " + (row.original.Class === "down" ? "border-destructive/40 text-destructive" : row.original.Class === "ok" ? "border-primary/40 text-primary" : "text-muted-foreground")}>{row.original.type}</Badge> },
    { id: "title", header: "Was", accessorFn: (r) => r.Title },
    { id: "info", header: "Details", accessorFn: (r) => r.Info, cell: ({ getValue }) => <span className="text-muted-foreground">{String(getValue())}</span> },
  ]
  if (!d) return <Skeleton className="h-64" />
  const dev = d.device
  const host = d.host
  return (
    <>
      <PageHeader crumbs={[{ label: "Kunden", to: "/tenants" }, { label: d.tenant.Name, to: `/tenants/${d.tenant.ID}` }, { label: d.site.Name, to: `/sites/${d.site.ID}` }, { label: dev.Name }]}
        title={<><KindIcon kind={dev.Kind} className={"size-6 " + (dev.Monitored ? "text-primary" : "text-muted-foreground")} />{dev.Name}{dev.Monitored && <StateBadge cls={dev.StateClass} label={dev.StateLabel} />}{dev.IsUplink && <Badge variant="outline" className="border-primary/40 text-primary">Uplink</Badge>}{dev.IsBox && <Badge variant="secondary">diese Box</Badge>}</>}
        sub={<span>{dev.KindLabel} · <span className="font-mono">{dev.IP || "keine IPv4"}</span> · {dev.Vendor || "Hersteller unbekannt"}</span>}
        actions={!dev.IsBox && <label className="flex items-center gap-2 text-sm"><span className="text-muted-foreground">Beobachten</span><Switch checked={dev.Monitored} disabled={!dev.IP || act.isPending} onCheckedChange={(on) => act.mutate({ path: on ? `/api/devices/${dev.ID}/watch` : `/api/hosts/${dev.HostID}/unwatch` })} /></label>} />

      <StatGrid>
        <StatCard label="Zustand" value={dev.Monitored ? dev.StateLabel : "nicht beobachtet"} tone={dev.Monitored ? (dev.StateClass === "down" ? "bad" : dev.StateClass === "up" ? "ok" : undefined) : undefined}
          line1={host && !host.State.Since.startsWith("0001") ? <>seit <Ago t={host.State.Since} /></> : dev.Monitored ? "noch keine Prüfung" : "Einschalten, dann prüft die Box jede Minute"} line2={host ? `Prüfung ${host.Checks}` : "ICMP-Ping von der Box im LAN"} />
        <StatCard label="Verfügbarkeit 24 h" value={host ? `${pct(host.Avail.Pct)} %` : "–"} tone={host && host.Avail.Pct < 90 ? "bad" : undefined} line1={host ? `${host.Avail.Failed} von ${host.Avail.Rounds} Prüfungen fehlgeschlagen` : "Erst mit Beobachtung"} line2={host?.IsUplink ? "Uplink: meldet für alle dahinter" : host?.UplinkName ? `hinter ${host.UplinkName}` : "kein Uplink zugeordnet"} />
        <StatCard label="Im Netz seit" value={<span className="text-xl">{fmtDateTime(dev.FirstSeen)}</span>} line1={dev.GoneAt ? <span className="text-destructive">weg seit <Ago t={dev.GoneAt} /></span> : <>zuletzt gesehen <Ago t={dev.LastSeen} /></>} line2={dev.Ignored ? "im Inventar ignoriert" : "aus der Discovery der Box"} />
        <StatCard label="Ereignisse" value={d.events?.length ?? 0} line1={d.events?.[0]?.Title ?? "Kein Ereignis"} line2={d.events?.[0] ? `zuletzt ${fmtTime(d.events[0].occurred_at)}` : "letzte 24 Stunden"} />
      </StatGrid>

      <Tabs value={tab} onValueChange={(t) => { const p = new URLSearchParams(params); p.set("tab", t); setParams(p, { replace: true }) }}>
        <TabsList>
          <TabsTrigger value="uebersicht">Übersicht</TabsTrigger>
          <TabsTrigger value="ueberwachung">Überwachung</TabsTrigger>
          <TabsTrigger value="ereignisse">Ereignisse <Badge variant="secondary" className="ml-1">{d.events?.length ?? 0}</Badge></TabsTrigger>
          <TabsTrigger value="logs"><ScrollText className="size-3.5" />Logs</TabsTrigger>
          <TabsTrigger value="integrationen"><Plug className="size-3.5" />Integrationen</TabsTrigger>
          <TabsTrigger value="ki"><Bot className="size-3.5" />KI</TabsTrigger>
        </TabsList>

        <TabsContent value="uebersicht" className="mt-4 grid gap-4 @4xl/main:grid-cols-2">
          <Card>
            <CardHeader><CardTitle>Gerät</CardTitle><CardDescription>Was die Box über das Gerät weiß.</CardDescription></CardHeader>
            <CardContent className="flex flex-col gap-3">
              <Row k="Name">{dev.Name}{dev.Hostname && dev.Hostname !== dev.Name ? <span className="text-muted-foreground"> · meldet sich als {dev.Hostname}</span> : ""}</Row>
              <Row k="Art">{dev.KindLabel}</Row>
              <Row k="IPv4" mono>{dev.IP || "–"}</Row>
              <Row k="MAC" mono>{dev.MAC || "–"}</Row>
              <Row k="Hersteller">{dev.Vendor || "unbekannt (keine OUI-Zuordnung)"}</Row>
              <Row k="Zuerst gesehen">{fmtDateTime(dev.FirstSeen)}</Row>
              <Row k="Zuletzt gesehen">{fmtDateTime(dev.LastSeen)}</Row>
              <Row k="Kennung" mono>{dev.ID}</Row>
              <div className="flex gap-2 pt-2">
                <Button variant="outline" size="sm" onClick={() => act.mutate({ path: `/api/devices/${dev.ID}/ignore`, form: { ignored: dev.Ignored ? "0" : "1" } })}>{dev.Ignored ? "Nicht mehr ignorieren" : "Ignorieren"}</Button>
                {host && <Button variant="outline" size="sm" asChild><Link to={`/hosts/${host.ID}`}>Host-Einstellungen</Link></Button>}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Standort</CardTitle><CardDescription>Wo das Gerät hängt.</CardDescription></CardHeader>
            <CardContent className="flex flex-col gap-3">
              <Row k="Kunde"><Link className="hover:underline" to={`/tenants/${d.tenant.ID}`}>{d.tenant.Name}</Link></Row>
              <Row k="Standort"><Link className="hover:underline" to={`/sites/${d.site.ID}`}>{d.site.Name}</Link></Row>
              <Row k="Kennung" mono>{d.site.ID}</Row>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ueberwachung" className="mt-4">
          {host ? (
            <Card>
              <CardHeader><CardTitle>Verfügbarkeit je Stunde</CardTitle><CardDescription>letzte 24 Stunden · {host.Avail.Rounds} Prüfungen · {host.Avail.Failed} fehlgeschlagen</CardDescription></CardHeader>
              <CardContent>
                <div className="flex h-10 gap-1">{host.Avail.Hours.map((h, i) => <div key={i} title={`${h.Label}: ${h.Pct < 0 ? "keine Daten" : pct(h.Pct) + " %"}`} className={"flex-1 rounded-sm " + (h.Class === "ok" ? "bg-primary" : h.Class === "down" ? "bg-destructive" : h.Class === "warn" ? "bg-muted-foreground" : "bg-muted")} />)}</div>
                <div className="mt-2 flex justify-between font-mono text-xs text-muted-foreground">{host.Avail.Hours.filter((_, i) => i % 6 === 0 || i === 23).map((h) => <span key={h.Label}>{h.Label}</span>)}</div>
                <div className="mt-4 grid gap-3 text-sm @2xl/main:grid-cols-2">
                  <Row k="Beobachtet">{host.State.Observed}</Row><Row k="Gemeldet">{host.State.Reported}{host.Suppressed ? ` (unterdrückt: ${host.Suppressed})` : ""}</Row>
                  <Row k="Fehlschläge in Folge">{host.State.Failures}</Row><Row k="Erfolge in Folge">{host.State.Successes}</Row>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Empty className="border"><EmptyHeader><EmptyMedia variant="icon"><Radar /></EmptyMedia><EmptyTitle>Noch nicht beobachtet</EmptyTitle><EmptyDescription>Oben rechts einschalten, dann prüft die Box das Gerät jede Minute und hier entsteht die Verfügbarkeit.</EmptyDescription></EmptyHeader></Empty>
          )}
        </TabsContent>

        <TabsContent value="ereignisse" className="mt-4">
          <DataTable columns={evCols} data={d.events ?? []} rowClass={(r) => r.Class === "down" ? "border-l-2 border-l-destructive" : ""} emptyTitle="Alles ruhig" emptyText="Kein Ereignis in den letzten 24 Stunden." />
        </TabsContent>

        <TabsContent value="logs" className="mt-4">
          <Empty className="border"><EmptyHeader><EmptyMedia variant="icon"><FileText /></EmptyMedia><EmptyTitle>Logs je Gerät kommen mit Phase 2</EmptyTitle><EmptyDescription>{d.logsNote} Geplant: Syslog der Firewall, Agent-Logs, Zeitraum und Filter, Live-Ansicht.</EmptyDescription></EmptyHeader></Empty>
        </TabsContent>
        <TabsContent value="integrationen" className="mt-4">
          <Empty className="border"><EmptyHeader><EmptyMedia variant="icon"><Plug /></EmptyMedia><EmptyTitle>Integrationen kommen mit dem Vollausbau</EmptyTitle><EmptyDescription>Geräte-APIs lesen (FortiGate, Proxmox, TrueNAS, SNMP) läuft dann von der Box aus, mit Zugangsdaten nur auf der Box. Das Konzept steht als Vorgang in salt.</EmptyDescription></EmptyHeader></Empty>
        </TabsContent>
        <TabsContent value="ki" className="mt-4">
          <Empty className="border"><EmptyHeader><EmptyMedia variant="icon"><Bot /></EmptyMedia><EmptyTitle>KI-Hinweise kommen nach den Regeln</EmptyTitle><EmptyDescription>Erst deterministische Regeln über Logs und Ereignisse, dann die LLM-Triage obendrauf, die Rauschen filtert und Alarme mit Kontext anreichert. Hier erscheint dann, was die KI zu diesem Gerät sagt.</EmptyDescription></EmptyHeader></Empty>
        </TabsContent>
      </Tabs>
      <span className="hidden" onClick={() => navigate("/")} />
    </>
  )
}
