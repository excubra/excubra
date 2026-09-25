import { Link, useNavigate, useParams, useSearchParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { Network, Plug, Radar, ScrollText, ShieldAlert, ShieldCheck } from "lucide-react"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { EventList } from "@/components/event-list"
import { StatCard, StatGrid } from "@/components/stat-card"
import { DataTable } from "@/components/data-table"
import { StateBadge } from "@/components/status"
import { DeviceMark } from "@/components/kind-icon"
import { ConnectIP, ServicePort } from "@/components/connect"
import { Ago } from "@/components/clock"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { PatchPanel } from "@/components/patch-panel"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { get, post, type DeviceDetail, type ServiceRow } from "@/lib/api"
import { ConnectorPanel } from "@/components/connector-panel"
import { DeviceFindings } from "@/components/device-findings"
import { SourceLogs } from "@/components/source-logs"
import { fmtDateTime, fmtTime, pct } from "@/lib/format"

function Row({ k, children, mono }: { k: string; children: React.ReactNode; mono?: boolean }) {
  return <div className="grid grid-cols-[150px_1fr] gap-3 text-sm"><span className="text-muted-foreground">{k}</span><span className={mono ? "font-mono text-[13px]" : ""}>{children}</span></div>
}

export default function DevicePage() {
  const { id = "" } = useParams()
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["device", id], queryFn: () => get<DeviceDetail>(`/api/devices/${id}`) })
  // An application that reports itself has its logs where a device has its overview.
  const tab = params.get("tab") || (q.data?.source ? "logs" : "uebersicht")
  const act = useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post(path, form),
    onSuccess: (r) => { toast.success(r.message); qc.invalidateQueries({ queryKey: ["device", id] }) },
    onError: (e) => toast.error(e.message),
  })
  const d = q.data
  const deviceIP = d?.device.IP ?? ""
  const deviceWays = d?.device.Ways ?? []
  const svcCols: ColumnDef<ServiceRow, unknown>[] = [
    { id: "port", header: "Port", accessorFn: (r) => r.Port, cell: ({ row }) => <ServicePort proto={row.original.Proto} port={row.original.Port} ip={deviceIP} ways={deviceWays} gone={!!row.original.GoneAt} /> },
    { id: "name", header: "Dienst", accessorFn: (r) => r.Name, cell: ({ row }) => <span>{row.original.Name || "–"}{row.original.New && <Badge variant="outline" className="ml-2 border-primary/40 text-primary">neu</Badge>}{row.original.GoneAt && <Badge variant="secondary" className="ml-2">weg</Badge>}</span> },
    { id: "product", header: "Produkt", accessorFn: (r) => `${r.Product} ${r.Version}`, cell: ({ row }) => <span>{row.original.Product ? <>{row.original.Product}{row.original.Version && <span className="font-mono text-xs text-muted-foreground"> {row.original.Version}</span>}</> : <span className="text-muted-foreground">–</span>}</span> },
    { id: "banner", header: "Meldet sich als", accessorFn: (r) => r.Title || r.Banner, cell: ({ getValue }) => <span className="text-muted-foreground">{String(getValue() || "–")}</span> },
    { id: "tls", header: "Zertifikat", accessorFn: (r) => r.TLSInfo?.not_after ?? "", cell: ({ row }) => { const t = row.original.TLSInfo; if (!t) return <span className="text-muted-foreground">–</span>; const exp = new Date(t.not_after); const days = Math.floor((exp.getTime() - Date.now()) / 86400000); return <span className={days < 0 ? "text-destructive" : days < 14 ? "text-foreground" : "text-muted-foreground"}>TLS {t.version} · {days < 0 ? `abgelaufen seit ${-days} Tagen` : `läuft in ${days} Tagen ab`}{t.self_signed ? " · selbstsigniert" : ""}</span> } },
    { id: "seen", header: "Gesehen", accessorFn: (r) => r.LastSeen, cell: ({ row }) => <span className="text-muted-foreground">seit {fmtDateTime(row.original.FirstSeen)}{row.original.GoneAt ? `, weg seit ${fmtDateTime(row.original.GoneAt)}` : ""}</span> },
  ]
  if (!d) return <Skeleton className="h-64" />
  const dev = d.device
  const host = d.host
  const src = d.source
  const openServices = (d.services ?? []).filter((s) => !s.GoneAt).length
  // The ways in come with the device, worked out on the server from the scan and
  // the connectors — not from a table of port numbers in the browser.
  const ways = d.device.Ways ?? []
  return (
    <>
      <PageHeader crumbs={[{ label: "Kunden", to: "/tenants" }, { label: d.tenant.Name, to: `/tenants/${d.tenant.ID}` }, { label: d.site.Name, to: `/sites/${d.site.ID}` }, { label: dev.Name }]}
        title={<><DeviceMark kind={dev.Kind} vendor={dev.Vendor} className={"size-6 " + (dev.Monitored ? "text-primary" : "text-muted-foreground")} />{dev.Name}{dev.Monitored && <StateBadge cls={dev.StateClass} label={dev.StateLabel} />}{dev.IsUplink && <Badge variant="outline" className="border-primary/40 text-primary">Uplink</Badge>}{dev.IsBox && <Badge variant="secondary">diese Box</Badge>}{src && <Badge variant="outline">meldet sich selbst</Badge>}</>}
        sub={<span className="flex flex-wrap items-center gap-x-1.5 gap-y-1">{dev.KindLabel} · <ConnectIP ip={dev.IP} ways={ways} />{!src && <> · {dev.Vendor || "Hersteller unbekannt"}</>}</span>}
        actions={!dev.IsBox && !src && <label className="flex items-center gap-2 text-sm"><span className="text-muted-foreground">Beobachten</span><Switch checked={dev.Monitored} disabled={!dev.IP || act.isPending} onCheckedChange={(on) => act.mutate({ path: on ? `/api/devices/${dev.ID}/watch` : `/api/hosts/${dev.HostID}/unwatch` })} /></label>} />

      {src ? (
        <StatGrid>
          <StatCard label="Meldet sich" value={src.silent ? "still" : "ja"} tone={src.silent ? "bad" : "ok"}
            line1={<>letzte Meldung <Ago t={src.lastContact} /></>} line2={`still heißt: ${src.silentAfterMin} Minuten ohne Meldung`} />
          <StatCard label="Offene Befunde" value={src.openFindings} tone={src.openFindings > 0 ? "bad" : undefined} to={`/devices/${dev.ID}?tab=praevention`}
            line1={src.openFindings > 0 ? "aus dem, was sie gemeldet hat" : "nichts Auffälliges"} line2="die Regeln prüfen jede Meldung" />
          <StatCard label="Angelegt" value={<span className="text-xl">{fmtDateTime(dev.FirstSeen)}</span>} line1="als Quelle mit eigenem Token" line2="der Token kann nur melden, nichts lesen" />
          <StatCard label="Ereignisse" value={d.events?.length ?? 0} line1={d.events?.[0]?.Title ?? "Kein Ereignis"} line2={d.events?.[0] ? `zuletzt ${fmtTime(d.events[0].occurred_at)}` : "letzte 24 Stunden"} />
        </StatGrid>
      ) : (
        <StatGrid>
          <StatCard label="Zustand" value={dev.Monitored ? dev.StateLabel : "nicht beobachtet"} tone={dev.Monitored ? (dev.StateClass === "down" ? "bad" : dev.StateClass === "up" ? "ok" : undefined) : undefined}
            line1={host && !host.State.Since.startsWith("0001") ? <>seit <Ago t={host.State.Since} /></> : dev.Monitored ? "noch keine Prüfung" : "Einschalten, dann prüft die Box jede Minute"} line2={host ? `Prüfung ${host.Checks}` : "ICMP-Ping von der Box im LAN"} />
          <StatCard label="Verfügbarkeit 24 h" value={host ? `${pct(host.Avail.Pct)} %` : "–"} tone={host && host.Avail.Pct < 90 ? "bad" : undefined} line1={host ? `${host.Avail.Failed} von ${host.Avail.Rounds} Prüfungen fehlgeschlagen` : "Erst mit Beobachtung"} line2={host?.IsUplink ? "Uplink: meldet für alle dahinter" : host?.UplinkName ? `hinter ${host.UplinkName}` : "kein Uplink zugeordnet"} />
          <StatCard label="Im Netz seit" value={<span className="text-xl">{fmtDateTime(dev.FirstSeen)}</span>} line1={dev.GoneAt ? <span className="text-destructive">weg seit <Ago t={dev.GoneAt} /></span> : <>zuletzt gesehen <Ago t={dev.LastSeen} /></>} line2={dev.Ignored ? "im Inventar ignoriert" : "aus der Discovery der Box"} />
          <StatCard label="Ereignisse" value={d.events?.length ?? 0} line1={d.events?.[0]?.Title ?? "Kein Ereignis"} line2={d.events?.[0] ? `zuletzt ${fmtTime(d.events[0].occurred_at)}` : "letzte 24 Stunden"} />
        </StatGrid>
      )}

      <Tabs value={tab} onValueChange={(t) => { const p = new URLSearchParams(params); p.set("tab", t); setParams(p, { replace: true }) }}>
        <TabsList>
          <TabsTrigger value="uebersicht">Übersicht</TabsTrigger>
          {!src && <TabsTrigger value="ueberwachung">Überwachung</TabsTrigger>}
          <TabsTrigger value="ereignisse">Ereignisse <Badge variant="secondary" className="ml-1">{d.events?.length ?? 0}</Badge></TabsTrigger>
          {!src && <TabsTrigger value="dienste"><Network className="size-3.5" />Dienste <Badge variant="secondary" className="ml-1">{openServices}</Badge></TabsTrigger>}
          <TabsTrigger value="logs"><ScrollText className="size-3.5" />Logs</TabsTrigger>
          {!src && <TabsTrigger value="konnektor"><Plug className="size-3.5" />Konnektor</TabsTrigger>}
          {!src && <TabsTrigger value="patch"><ShieldCheck className="size-3.5" />Patch-Stand</TabsTrigger>}
          <TabsTrigger value="praevention"><ShieldAlert className="size-3.5" />Prävention</TabsTrigger>
        </TabsList>

        <TabsContent value="uebersicht" className="mt-4 grid gap-4 @4xl/main:grid-cols-2">
          <Card>
            <CardHeader><CardTitle>Gerät</CardTitle><CardDescription>{src ? "Eine Anwendung, die ihre Ereignisse selbst schickt. Keine Box sieht sie, deshalb hat sie keine MAC." : "Was die Box über das Gerät weiß."}</CardDescription></CardHeader>
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
          <EventList events={d.events ?? []} showWhere={false} emptyTitle="Alles ruhig" emptyText="Kein Ereignis in den letzten 24 Stunden." />
        </TabsContent>

        <TabsContent value="dienste" className="mt-4">
          {(d.services ?? []).length > 0
            ? <DataTable columns={svcCols} data={d.services ?? []} rowClass={(r) => r.GoneAt ? "opacity-60" : ""} initialSort={[{ id: "port", desc: false }]} emptyTitle="Nichts gefunden" />
            : <Empty className="border"><EmptyHeader><EmptyMedia variant="icon"><Network /></EmptyMedia><EmptyTitle>Noch kein Scan</EmptyTitle><EmptyDescription>Der Schwachstellen-Scan wird am Standort unter Box &amp; Technik eingeschaltet. Die Box tastet die Geräte dann täglich ab: Dienste, Versionen, Zertifikate.</EmptyDescription></EmptyHeader></Empty>}
        </TabsContent>
        <TabsContent value="logs" className="mt-4">
          <SourceLogs deviceId={id} note={d.logsNote} />
        </TabsContent>
        <TabsContent value="konnektor" className="mt-4">
          <ConnectorPanel deviceId={id} />
        </TabsContent>
        <TabsContent value="patch" className="mt-4">
          <PatchPanel deviceId={d.device.ID} />
        </TabsContent>

        <TabsContent value="praevention" className="mt-4">
          <DeviceFindings deviceId={id} />
        </TabsContent>
      </Tabs>
      <span className="hidden" onClick={() => navigate("/")} />
    </>
  )
}
