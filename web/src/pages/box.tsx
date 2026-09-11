import { Link, useParams } from "react-router"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { PageHeader } from "@/components/page-header"
import { BoxTech } from "@/components/box-tech"
import { StateBadge, boxClass } from "@/components/status"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type BoxData } from "@/lib/api"

export default function BoxPage() {
  const { id = "" } = useParams()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["box", id], queryFn: () => get<BoxData>(`/api/boxes/${id}`) })
  const d = q.data
  if (!d) return <Skeleton className="h-64" />
  const b = d.Row
  const c = boxClass(b.State.Status, b.State.LastHeartbeat)
  return (
    <>
      <PageHeader crumbs={[{ label: "Boxen", to: "/boxes" }, { label: b.Name || b.ID }]}
        title={<>{b.Name || <span className="font-mono">{b.ID}</span>}{c === "online" ? <StateBadge cls="ok" label="online" /> : c === "silent" ? <StateBadge cls="silent" label="schweigt" /> : <Badge variant="secondary">noch kein Heartbeat</Badge>}{!b.Assigned && <StateBadge cls="bad" label="nicht zugeordnet" />}</>}
        sub={b.Assigned ? <span>{b.TenantName} · <Link className="hover:underline" to={`/sites/${b.SiteID}`}>{b.SiteName}</Link></span> : "Unten einem Standort zuordnen, dann sieht EX0 das Netz dahinter."} />
      <BoxTech box={b} sites={d.Sites ?? []} tenantNames={d.TenantNames} fingerprint={d.Fingerprint} netbird={d.Netbird} subnets={d.Subnets} onChanged={() => { qc.invalidateQueries({ queryKey: ["box", id] }); qc.invalidateQueries({ queryKey: ["boxes"] }); qc.invalidateQueries({ queryKey: ["me"] }) }} />
    </>
  )
}
