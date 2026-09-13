import { Link, useNavigate } from "react-router"
import { useQuery } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { StateBadge } from "@/components/status"
import { Ago } from "@/components/clock"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type SiteRow } from "@/lib/api"
import { fmtTime } from "@/lib/format"

// Every site of every customer in one flat list. With fifty customers this, not the
// customer tree, is the way in: search, sort, one click to the site.
export default function SitesPage() {
  const navigate = useNavigate()
  const q = useQuery({ queryKey: ["sites"], queryFn: () => get<SiteRow[]>("/api/sites"), refetchInterval: 30_000 })
  const rows = q.data ?? []

  const cols: ColumnDef<SiteRow, unknown>[] = [
    {
      id: "site", header: "Standort", accessorFn: (r) => `${r.Site.Name} ${r.Tenant.Name}`,
      cell: ({ row }) => (
        <div className="min-w-0">
          <div className="truncate font-medium">{row.original.Site.Name}</div>
          <div className="truncate text-xs text-muted-foreground">{row.original.Tenant.Name}</div>
        </div>
      ),
    },
    {
      id: "state", header: "Zustand", accessorFn: (r) => (!r.HasBox ? 0 : !r.Online ? 3 : r.Down ? 2 : 1),
      cell: ({ row }) => {
        const r = row.original
        return !r.HasBox ? <Badge variant="secondary">ohne Box</Badge>
          : !r.Online ? <StateBadge cls="silent" label="Box schweigt" />
            : r.Down ? <StateBadge cls="down" label={`${r.Down} ausgefallen`} />
              : <StateBadge cls="ok" label="online" />
      },
    },
    {
      id: "findings", header: "Prävention", accessorFn: (r) => r.findings, meta: { align: "right" },
      cell: ({ row }) => row.original.findings > 0
        ? <Link to="/findings" className="font-semibold text-destructive hover:underline">{row.original.findings}</Link>
        : <span className="text-muted-foreground">–</span>,
    },
    {
      id: "box", header: "Box", accessorFn: (r) => r.Box?.Name ?? "", meta: { className: "hidden md:table-cell" },
      cell: ({ row }) => row.original.HasBox
        ? <div><div className="truncate font-mono text-xs">{row.original.Box!.Name || row.original.Box!.ID}</div><div className="text-xs text-muted-foreground">Heartbeat <Ago t={row.original.Box!.State.LastHeartbeat} /></div></div>
        : <span className="text-muted-foreground">–</span>,
    },
    { id: "mon", header: "Beobachtet", accessorFn: (r) => r.Monitored, meta: { align: "right", className: "hidden lg:table-cell" } },
    {
      id: "down", header: "Ausgefallen", accessorFn: (r) => r.Down, meta: { align: "right", className: "hidden lg:table-cell" },
      cell: ({ getValue }) => <span className={Number(getValue()) > 0 ? "font-semibold text-destructive" : ""}>{String(getValue())}</span>,
    },
    { id: "devices", header: "Geräte", accessorFn: (r) => r.Devices, meta: { align: "right", className: "hidden lg:table-cell" } },
    {
      id: "last", header: "Zuletzt", accessorFn: (r) => r.Last?.occurred_at ?? "", meta: { className: "hidden xl:table-cell" },
      cell: ({ row }) => row.original.Last
        ? <span className="text-muted-foreground"><span className="font-mono text-xs">{fmtTime(row.original.Last.occurred_at)}</span> {row.original.Last.Title}</span>
        : <span className="text-muted-foreground">–</span>,
    },
  ]

  const down = rows.filter((r) => r.HasBox && (!r.Online || r.Down > 0)).length
  const findings = rows.reduce((a, r) => a + r.findings, 0)
  return (
    <>
      <PageHeader
        crumbs={[{ label: "Standorte" }]}
        title="Standorte"
        sub={rows.length ? <>{rows.length} Standorte bei {new Set(rows.map((r) => r.Tenant.ID)).size} Kunden · {down ? <span className="text-destructive">{down} mit Störung</span> : "alle ruhig"}{findings ? <> · {findings} offene Findings</> : null}</> : "Jeder Standort, quer über alle Kunden. Suchen, sortieren, ein Klick hinein."}
      />
      {q.isLoading ? <Skeleton className="h-96" /> : (
        <DataTable
          columns={cols} data={rows} pageSize={50}
          search={(r) => `${r.Site.Name} ${r.Tenant.Name} ${r.Box?.Name ?? ""} ${r.Box?.ID ?? ""}`}
          searchPlaceholder="Standort, Kunde oder Box"
          onRowClick={(r) => navigate(`/sites/${r.Site.ID}`)}
          rowClass={(r) => (r.HasBox && (!r.Online || r.Down > 0) ? "border-l-2 border-l-destructive" : "")}
          initialSort={[{ id: "state", desc: true }]}
          emptyTitle="Noch kein Standort"
          emptyText={<span>Unter <Link className="underline" to="/tenants">Kunden</Link> den ersten Kunden und Standort anlegen.</span>}
        />
      )}
    </>
  )
}
