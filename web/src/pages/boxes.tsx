import { Link, useNavigate } from "react-router"
import { useQuery } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { KeyRound } from "lucide-react"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { StateBadge, boxClass } from "@/components/status"
import { Ago } from "@/components/clock"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { get, type BoxRow, type BoxesData } from "@/lib/api"
import { fmtShort, gb } from "@/lib/format"

export default function BoxesPage() {
  const navigate = useNavigate()
  const q = useQuery({ queryKey: ["boxes"], queryFn: () => get<BoxesData>("/api/boxes") })
  const all = [...(q.data?.Unassigned ?? []), ...(q.data?.Assigned ?? [])]
  const cols: ColumnDef<BoxRow, unknown>[] = [
    { id: "name", header: "Box", accessorFn: (r) => r.Name || r.ID, cell: ({ row }) => <div><div className="font-medium">{row.original.Name || <span className="font-mono">{row.original.ID}</span>}</div>{row.original.Name && <div className="font-mono text-xs text-muted-foreground">{row.original.ID}</div>}</div> },
    { id: "site", header: "Standort", accessorFn: (r) => (r.Assigned ? `${r.TenantName} ${r.SiteName}` : ""), cell: ({ row }) => row.original.Assigned ? <span>{row.original.TenantName} · <Link className="hover:underline" to={`/sites/${row.original.SiteID}`}>{row.original.SiteName}</Link></span> : <StateBadge cls="bad" label="nicht zugeordnet" /> },
    { id: "state", header: "Zustand", accessorFn: (r) => boxClass(r.State.Status, r.State.LastHeartbeat), cell: ({ row }) => { const c = boxClass(row.original.State.Status, row.original.State.LastHeartbeat); return c === "online" ? <StateBadge cls="ok" label="online" /> : c === "silent" ? <StateBadge cls="silent" label="schweigt" /> : <Badge variant="secondary">noch kein Heartbeat</Badge> } },
    { id: "hb", header: "Heartbeat", accessorFn: (r) => r.State.LastHeartbeat, cell: ({ row }) => <span className="text-muted-foreground"><Ago t={row.original.State.LastHeartbeat} /></span> },
    { id: "agent", header: "Agent", accessorFn: (r) => r.AgentVersion, cell: ({ row }) => <span className="font-mono text-xs">{row.original.AgentVersion || "–"} <Badge variant="secondary">{row.original.Channel}</Badge></span> },
    { id: "plat", header: "Plattform", accessorFn: (r) => `${r.OS}/${r.Arch}` },
    { id: "nb", header: "NetBird", accessorFn: (r) => r.NetbirdStatus, cell: ({ row }) => row.original.NetbirdStatus === "connected" ? <StateBadge cls="ok" label={row.original.NetbirdIP || "verbunden"} /> : <span className="text-muted-foreground">{row.original.NetbirdStatus || "–"}</span> },
    { id: "disk", header: "Platte", accessorFn: (r) => r.DiskFreeBytes, cell: ({ row }) => <span className="font-mono text-xs">{row.original.DiskTotalBytes ? `${gb(row.original.DiskFreeBytes)} / ${gb(row.original.DiskTotalBytes)} GB` : "–"}</span> },
    { id: "enrolled", header: "Enrollt", accessorFn: (r) => r.EnrolledAt, cell: ({ getValue }) => <span className="text-muted-foreground">{fmtShort(String(getValue()))}</span> },
  ]
  return (
    <>
      <PageHeader crumbs={[{ label: "Boxen" }]} title="Boxen" sub="Jede Box gehört zu genau einem Standort. Neue Boxen erscheinen hier nach dem Enrollment mit einem Key."
        actions={<Button asChild variant="outline" size="sm"><Link to="/keys"><KeyRound />Enrollment-Keys</Link></Button>} />
      <DataTable columns={cols} data={all} search={(r) => `${r.Name} ${r.ID} ${r.TenantName} ${r.SiteName} ${r.NetbirdIP}`} onRowClick={(r) => navigate(`/boxes/${r.ID}`)} initialSort={[{ id: "site", desc: false }]} rowClass={(r) => !r.Assigned || r.State.Status === "silent" ? "border-l-2 border-l-destructive" : ""} emptyTitle="Noch keine Box" emptyText="Neue Boxen erscheinen nach dem Enrollment mit einem Key." />
    </>
  )
}
