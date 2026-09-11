import { Link, useParams } from "react-router"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { PageHeader } from "@/components/page-header"
import { BoxTech } from "@/components/box-tech"
import { TaskMenu } from "@/components/task-menu"
import { NoteList, TaskList } from "@/components/task-list"
import { StateBadge, boxClass } from "@/components/status"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type BoxData } from "@/lib/api"

export default function BoxPage() {
  const { id = "" } = useParams()
  const qc = useQueryClient()
  // Task results arrive with the box's heartbeats, so the page keeps looking.
  const q = useQuery({ queryKey: ["box", id], queryFn: () => get<BoxData>(`/api/boxes/${id}`), refetchInterval: 15_000 })
  const d = q.data
  if (!d) return <Skeleton className="h-64" />
  const b = d.Row
  const c = boxClass(b.State.Status, b.State.LastHeartbeat)
  const refresh = () => { qc.invalidateQueries({ queryKey: ["box", id] }); qc.invalidateQueries({ queryKey: ["boxes"] }); qc.invalidateQueries({ queryKey: ["me"] }) }
  const pending = (d.Tasks ?? []).filter((t) => !t.DoneAt).length
  return (
    <>
      <PageHeader crumbs={[{ label: "Boxen", to: "/boxes" }, { label: b.Name || b.ID }]}
        title={<>{b.Name || <span className="font-mono">{b.ID}</span>}{c === "online" ? <StateBadge cls="ok" label="online" /> : c === "silent" ? <StateBadge cls="silent" label="schweigt" /> : <Badge variant="secondary">noch kein Heartbeat</Badge>}{!b.Assigned && <StateBadge cls="bad" label="nicht zugeordnet" />}{pending > 0 && <Badge variant="secondary">{pending === 1 ? "1 Aufgabe wartet" : `${pending} Aufgaben warten`}</Badge>}</>}
        sub={b.Assigned ? <span>{b.TenantName} · <Link className="hover:underline" to={`/sites/${b.SiteID}`}>{b.SiteName}</Link></span> : "Unten einem Standort zuordnen, dann sieht EX0 das Netz dahinter."}
        actions={<TaskMenu path={`/api/boxes/${id}/tasks`} onDone={refresh} />} />
      <BoxTech box={b} sites={d.Sites ?? []} tenantNames={d.TenantNames} fingerprint={d.Fingerprint} netbird={d.Netbird} subnets={d.Subnets} onChanged={refresh} />
      <div className="grid gap-4 @4xl/main:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Aufgaben</CardTitle><CardDescription>Was die Konsole der Box aufgetragen hat, neueste zuerst. Ergebnisse kommen mit dem Heartbeat.</CardDescription></CardHeader>
          <CardContent><TaskList tasks={d.Tasks ?? []} /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Meldungen der Box</CardTitle><CardDescription>Was der Agent einem Menschen sagen wollte: Rollbacks, abgelehnte Updates, NetBird.</CardDescription></CardHeader>
          <CardContent><NoteList notes={d.Notes ?? []} /></CardContent>
        </Card>
      </div>
    </>
  )
}
