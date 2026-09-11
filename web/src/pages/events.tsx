import { useNavigate, useSearchParams } from "react-router"
import { useQuery } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { Badge } from "@/components/ui/badge"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { get, type EventRow, type TenantRow } from "@/lib/api"
import { fmtDateTime } from "@/lib/format"

const types = ["host.down", "host.up", "box.silent", "box.back", "device.new", "device.gone", "maintenance.started", "maintenance.ended", "test.ping"]

export default function EventsPage() {
  const [params, setParams] = useSearchParams()
  const range = params.get("range") || "24h"
  const tenant = params.get("tenant") || ""
  const site = params.get("site") || ""
  const type = params.get("type") || ""
  const navigate = useNavigate()
  const q = useQuery({ queryKey: ["events", range, tenant, site, type], queryFn: () => get<{ range: string; events: EventRow[] | null }>("/api/events", { range, tenant, site, type }) })
  const tenants = useQuery({ queryKey: ["tenants"], queryFn: () => get<TenantRow[]>("/api/tenants") })
  const set = (k: string, v: string) => { const p = new URLSearchParams(params); if (v) p.set(k, v); else p.delete(k); setParams(p, { replace: true }) }
  const rows = q.data?.events ?? []
  const cols: ColumnDef<EventRow, unknown>[] = [
    { id: "t", header: "Zeit", accessorFn: (r) => r.occurred_at, cell: ({ getValue }) => <span className="font-mono text-xs">{fmtDateTime(String(getValue()))}</span> },
    { id: "type", header: "Ereignis", accessorFn: (r) => r.type, cell: ({ row }) => <Badge variant="outline" className={"font-mono " + (row.original.Class === "down" ? "border-destructive/40 text-destructive" : row.original.Class === "ok" ? "border-primary/40 text-primary" : "text-muted-foreground")}>{row.original.type}</Badge> },
    { id: "title", header: "Was", accessorFn: (r) => r.Title },
    { id: "where", header: "Kunde · Standort", accessorFn: (r) => `${r.TenantName} ${r.SiteName}`, cell: ({ row }) => <span>{row.original.TenantName}{row.original.SiteName ? ` · ${row.original.SiteName}` : ""}</span> },
    { id: "info", header: "Details", accessorFn: (r) => r.Info, cell: ({ getValue }) => <span className="text-muted-foreground">{String(getValue())}</span> },
  ]
  return (
    <>
      <PageHeader crumbs={[{ label: "Ereignisse" }]} title="Ereignisse" sub="Nur Zustandswechsel, keine Logs. Rot ist ein Ausfall, grün eine Rückkehr, grau Information." />
      <DataTable columns={cols} data={rows} search={(r) => `${r.type} ${r.Title} ${r.TenantName} ${r.SiteName} ${r.Info}`} pageSize={50}
        toolbar={
          <>
            <ToggleGroup type="single" value={range} onValueChange={(v) => v && set("range", v)} variant="outline" size="sm">
              <ToggleGroupItem value="24h">24 h</ToggleGroupItem><ToggleGroupItem value="7d">7 Tage</ToggleGroupItem><ToggleGroupItem value="30d">30 Tage</ToggleGroupItem>
            </ToggleGroup>
            <Select value={tenant || "__all"} onValueChange={(v) => set("tenant", v === "__all" ? "" : v)}>
              <SelectTrigger size="sm" className="w-56"><SelectValue placeholder="Alle Kunden" /></SelectTrigger>
              <SelectContent><SelectItem value="__all">Alle Kunden</SelectItem>{(tenants.data ?? []).map((t) => <SelectItem key={t.ID} value={t.ID}>{t.Name}</SelectItem>)}</SelectContent>
            </Select>
            <Select value={type || "__all"} onValueChange={(v) => set("type", v === "__all" ? "" : v)}>
              <SelectTrigger size="sm" className="w-48"><SelectValue placeholder="Alle Arten" /></SelectTrigger>
              <SelectContent><SelectItem value="__all">Alle Arten</SelectItem>{types.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent>
            </Select>
            <ToggleGroup type="single" value={type === "host.down" ? "red" : ""} onValueChange={(v) => set("type", v === "red" ? "host.down" : "")} variant="outline" size="sm"><ToggleGroupItem value="red">Nur rot</ToggleGroupItem></ToggleGroup>
          </>
        }
        onRowClick={(r) => { if (r.host_id) navigate(`/hosts/${r.host_id}`); else if (r.device_id) navigate(`/devices/${r.device_id}`); else if (r.site_id) navigate(`/sites/${r.site_id}`) }}
        rowClass={(r) => r.Class === "down" ? "border-l-2 border-l-destructive" : ""} emptyTitle="Alles ruhig" emptyText="Kein Ereignis im gewählten Zeitraum." />
    </>
  )
}
