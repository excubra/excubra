import { useState } from "react"
import { Link, useNavigate, useParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { StatCard, StatGrid } from "@/components/stat-card"
import { DataTable } from "@/components/data-table"
import { StateBadge } from "@/components/status"
import { Ago } from "@/components/clock"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Checkbox } from "@/components/ui/checkbox"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { get, post, type EventRow, type HostData } from "@/lib/api"
import { fmtDateTime, pct } from "@/lib/format"

export default function HostPage() {
  const { id = "" } = useParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["host", id], queryFn: () => get<HostData>(`/api/hosts/${id}`) })
  const d = q.data
  const m = useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post(path, form),
    onSuccess: (r, v) => { toast.success(r.message); if (v.path.endsWith("/delete")) navigate(`/sites/${d?.Site.ID}?tab=ueberwachung`); else qc.invalidateQueries({ queryKey: ["host", id] }) },
    onError: (e) => toast.error(e.message),
  })
  const evCols: ColumnDef<EventRow, unknown>[] = [
    { id: "t", header: "Zeit", accessorFn: (r) => r.occurred_at, cell: ({ getValue }) => <span className="font-mono text-xs">{fmtDateTime(String(getValue()))}</span> },
    { id: "type", header: "Ereignis", accessorFn: (r) => r.type, cell: ({ row }) => <Badge variant="outline" className={"font-mono " + (row.original.Class === "down" ? "border-destructive/40 text-destructive" : row.original.Class === "ok" ? "border-primary/40 text-primary" : "text-muted-foreground")}>{row.original.type}</Badge> },
    { id: "title", header: "Was", accessorFn: (r) => r.Title },
    { id: "info", header: "Details", accessorFn: (r) => r.Info, cell: ({ getValue }) => <span className="text-muted-foreground">{String(getValue())}</span> },
  ]
  if (!d) return <Skeleton className="h-64" />
  const v = d.View
  // The settings form owns its draft; it is re-created when the saved values change.
  const formKey = [v.Name, v.Address, d.Form.ICMP, d.Form.TCPPort, d.Form.HTTPURL, v.ParentID, v.IsUplink].join("|")
  return (
    <>
      <PageHeader crumbs={[{ label: "Kunden", to: "/tenants" }, { label: d.Tenant.Name, to: `/tenants/${d.Tenant.ID}` }, { label: d.Site.Name, to: `/sites/${d.Site.ID}?tab=ueberwachung` }, { label: v.Name }]}
        title={<>{v.Name}<StateBadge cls={d.Row.StateClass} label={d.Row.StateLabel} />{v.IsUplink && <Badge variant="outline" className="border-primary/40 text-primary">Uplink</Badge>}</>}
        sub={<span className="font-mono">{v.Address}{v.MAC ? ` · ${v.MAC}` : ""}</span>}
        actions={v.DeviceID && <Button variant="outline" size="sm" asChild><Link to={`/devices/${v.DeviceID}`}>Gerät im Inventar</Link></Button>} />
      <StatGrid>
        <StatCard label="Verfügbarkeit 24 h" value={`${pct(d.Availability)} %`} tone={d.Availability >= 99.5 ? "ok" : d.Availability < 90 ? "bad" : undefined} line1={`${d.Failed} von ${d.Rounds} Prüfungen fehlgeschlagen`} line2="Prüfrunden der Box, je Minute" />
        <StatCard label="Zustand seit" value={<Ago t={v.State.Since} />} line1={fmtDateTime(v.State.Since)} line2={`gemeldet als ${v.State.Reported}${v.Suppressed ? `, unterdrückt: ${v.Suppressed}` : ""}`} />
        <StatCard label="Letzte Prüfung" value={<Ago t={v.State.LastBoxTime} />} line1={`${v.State.Failures} Fehlschläge / ${v.State.Successes} Erfolge in Folge`} line2={d.Row.Checks} />
        <StatCard label="Box" value={<span className="text-xl">{d.Box.Name || d.Box.ID}</span>} line1={v.ParentID ? `hinter ${d.Siblings?.find((s) => s.ID === v.ParentID)?.Name ?? v.ParentID}` : v.IsUplink ? "Uplink: meldet für alle dahinter" : "kein Uplink"} line2={`beobachtet seit ${fmtDateTime(v.CreatedAt)}`} to={`/boxes/${d.Box.ID}`} />
      </StatGrid>
      <Tabs defaultValue="verlauf">
        <TabsList><TabsTrigger value="verlauf">Verlauf</TabsTrigger><TabsTrigger value="einstellungen">Einstellungen</TabsTrigger><TabsTrigger value="wartung">Wartung</TabsTrigger></TabsList>
        <TabsContent value="verlauf" className="mt-4 flex flex-col gap-4">
          <Card>
            <CardHeader><CardTitle>Verfügbarkeit je Stunde</CardTitle><CardDescription>letzte 24 Stunden · {d.Rounds} Runden</CardDescription></CardHeader>
            <CardContent>
              <div className="flex h-10 gap-1">{(d.Hours ?? []).map((h, i) => <div key={i} title={`${h.Label}: ${h.Pct < 0 ? "keine Daten" : pct(h.Pct) + " %"}`} className={"flex-1 rounded-sm " + (h.Class === "ok" ? "bg-primary" : h.Class === "down" ? "bg-destructive" : h.Class === "warn" ? "bg-muted-foreground" : "bg-muted")} />)}</div>
              <div className="mt-2 flex justify-between font-mono text-xs text-muted-foreground">{(d.Hours ?? []).filter((_, i) => i % 6 === 0 || i === 23).map((h) => <span key={h.Label}>{h.Label}</span>)}</div>
            </CardContent>
          </Card>
          <DataTable columns={evCols} data={d.Events ?? []} rowClass={(r) => r.Class === "down" ? "border-l-2 border-l-destructive" : ""} emptyTitle="Keine Ereignisse" emptyText="In den letzten 24 Stunden hat sich der Zustand nicht geändert." />
        </TabsContent>
        <TabsContent value="einstellungen" className="mt-4 grid gap-4 @4xl/main:grid-cols-2">
          <HostSettings key={formKey} d={d} pending={m.isPending} onSave={(form) => m.mutate({ path: `/api/hosts/${id}`, form })} />
          <Card>
            <CardHeader><CardTitle>Überwachung beenden</CardTitle><CardDescription>Der Host verschwindet aus Status und Checks. Das Gerät bleibt im Inventar.</CardDescription></CardHeader>
            <CardContent>
              <AlertDialog>
                <AlertDialogTrigger asChild><Button variant="outline" className="text-destructive">Nicht mehr überwachen</Button></AlertDialogTrigger>
                <AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Host nicht mehr überwachen?</AlertDialogTitle><AlertDialogDescription>Die Prüfungen enden mit dem nächsten Heartbeat.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Abbrechen</AlertDialogCancel><AlertDialogAction onClick={() => m.mutate({ path: `/api/hosts/${id}/delete` })}>Beenden</AlertDialogAction></AlertDialogFooter></AlertDialogContent>
              </AlertDialog>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="wartung" className="mt-4">
          <Card>
            <CardHeader><CardTitle>Wartungsfenster</CardTitle><CardDescription>Während eines Fensters gibt es keine Ereignisse; am Ende genau einen Übergang, falls sich etwas geändert hat.</CardDescription></CardHeader>
            <CardContent className="flex flex-col gap-4">
              {(d.Windows ?? []).length ? <ul className="flex flex-col gap-2 text-sm">{(d.Windows ?? []).map((w) => <li key={w.ID} className="flex items-center gap-2"><Badge variant="secondary">{w.Scope}</Badge><span className="font-mono text-xs">{w.TargetID}</span><span className="text-muted-foreground">bis {fmtDateTime(w.Until)}{w.Reason ? ` · ${w.Reason}` : ""}</span></li>)}</ul> : <p className="text-sm text-muted-foreground">Kein Fenster aktiv.</p>}
              <MaintenanceForm pending={m.isPending} onSet={(form) => m.mutate({ path: `/api/hosts/${id}/maintenance`, form })} />
              {(d.Windows ?? []).length > 0 && <div><Button variant="outline" size="sm" onClick={() => m.mutate({ path: `/api/hosts/${id}/maintenance`, form: { action: "end" } })}>Wartung dieses Hosts beenden</Button></div>}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  )
}

function HostSettings({ d, pending, onSave }: { d: HostData; pending: boolean; onSave: (form: Record<string, string>) => void }) {
  const v = d.View
  const [name, setName] = useState(v.Name)
  const [address, setAddress] = useState(v.Address)
  const [icmp, setIcmp] = useState(d.Form.ICMP)
  const [tcp, setTcp] = useState(d.Form.TCPPort ? String(d.Form.TCPPort) : "")
  const [http, setHttp] = useState(d.Form.HTTPURL)
  const [parent, setParent] = useState(v.ParentID)
  const [uplink, setUplink] = useState(v.IsUplink)
  return (
    <Card>
      <CardHeader><CardTitle>Host</CardTitle><CardDescription>Checks laufen alle 30 Sekunden auf der Box.</CardDescription></CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid gap-2"><Label>Name</Label><Input value={name} onChange={(e) => setName(e.target.value)} /></div>
        <div className="grid gap-2"><Label>Adresse (IP oder Name)</Label><Input value={address} onChange={(e) => setAddress(e.target.value)} className="font-mono" /></div>
        <label className="flex items-center gap-2 text-sm"><Checkbox checked={icmp} onCheckedChange={(c) => setIcmp(!!c)} />ICMP-Ping</label>
        <div className="grid gap-4 @xl/main:grid-cols-2">
          <div className="grid gap-2"><Label>TCP-Port</Label><Input type="number" min={1} max={65535} value={tcp} onChange={(e) => setTcp(e.target.value)} placeholder="443" /></div>
          <div className="grid gap-2"><Label>HTTP-URL</Label><Input value={http} onChange={(e) => setHttp(e.target.value)} placeholder="https://…" /></div>
        </div>
        <div className="grid gap-2"><Label>Uplink dieses Hosts (Firewall, Router)</Label>
          <Select value={parent || "__none"} onValueChange={(c) => setParent(c === "__none" ? "" : c)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="__none">keiner</SelectItem>{(d.Siblings ?? []).map((s) => <SelectItem key={s.ID} value={s.ID}>{s.Name} ({s.Address})</SelectItem>)}</SelectContent></Select></div>
        <label className="flex items-center gap-2 text-sm"><Checkbox checked={uplink} onCheckedChange={(c) => setUplink(!!c)} />Dieser Host ist ein Uplink: sein Ausfall unterdrückt die Hosts dahinter</label>
        <div><Button onClick={() => onSave({ name, address, icmp: icmp ? "1" : "", tcp_port: tcp, http_url: http, parent_id: parent, is_uplink: uplink ? "1" : "" })} disabled={pending}>Speichern</Button></div>
      </CardContent>
    </Card>
  )
}

function MaintenanceForm({ pending, onSet }: { pending: boolean; onSet: (form: Record<string, string>) => void }) {
  const [until, setUntil] = useState("")
  const [reason, setReason] = useState("")
  return (
    <div className="grid gap-4 @xl/main:grid-cols-[auto_1fr_auto] @xl/main:items-end">
      <div className="grid gap-2"><Label>Wartung bis</Label><Input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} /></div>
      <div className="grid gap-2"><Label>Grund</Label><Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="z. B. Firmware-Update" /></div>
      <Button variant="outline" onClick={() => onSet({ until, reason })} disabled={!until || pending}>Setzen</Button>
    </div>
  )
}
