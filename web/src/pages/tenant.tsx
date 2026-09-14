import { useState } from "react"
import { Link, useNavigate, useParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { Plus } from "lucide-react"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { PinButton } from "@/components/pin-button"
import { PatchOrgCard } from "@/components/patch-org-card"
import { EventList } from "@/components/event-list"
import { DataTable } from "@/components/data-table"
import { StateBadge } from "@/components/status"
import { Ago } from "@/components/clock"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { get, post, type Me, type SiteCard, type TenantDetail } from "@/lib/api"
import { fmtTime } from "@/lib/format"

export default function TenantPage() {
  const { id = "" } = useParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const me = useQuery({ queryKey: ["me"], queryFn: () => get<Me>("/api/me") })
  const q = useQuery({ queryKey: ["tenant", id], queryFn: () => get<TenantDetail>(`/api/tenants/${id}`) })
  const [open, setOpen] = useState(false)
  const [slug, setSlug] = useState("")
  const [name, setName] = useState("")
  const create = useMutation({
    mutationFn: () => post(`/api/tenants/${id}/sites`, { slug, name }),
    onSuccess: (r) => { toast.success(r.message); setOpen(false); setSlug(""); setName(""); qc.invalidateQueries({ queryKey: ["tenant", id] }) },
    onError: (e) => toast.error(e.message),
  })
  const aiSet = useMutation({
    mutationFn: (scope: string) => post(`/api/tenants/${id}/ai`, { scope }),
    onSuccess: (r) => { toast.success(r.message); qc.invalidateQueries({ queryKey: ["tenant", id] }) },
    onError: (e) => toast.error(e.message),
  })
  const d = q.data
  const cols: ColumnDef<SiteCard, unknown>[] = [
    { id: "site", header: "Standort", accessorFn: (r) => r.Site.Name, cell: ({ row }) => <div><div className="font-medium">{row.original.Site.Name}</div><div className="font-mono text-xs text-muted-foreground">{row.original.Site.ID}</div></div> },
    { id: "box", header: "Box", accessorFn: (r) => r.Box?.Name ?? "", cell: ({ row }) => row.original.HasBox ? <div><span className="font-mono text-xs">{row.original.Box!.Name || row.original.Box!.ID}</span><div className="text-xs text-muted-foreground">Heartbeat <Ago t={row.original.Box!.State.LastHeartbeat} /></div></div> : <Badge variant="secondary">keine</Badge> },
    { id: "state", header: "Zustand", accessorFn: (r) => r.Class, cell: ({ row }) => { const r = row.original; return !r.HasBox ? <Badge variant="secondary">ohne Box</Badge> : !r.Online ? <StateBadge cls="silent" label="Box schweigt" /> : r.Down ? <StateBadge cls="down" label={`${r.Down} ausgefallen`} /> : <StateBadge cls="ok" label="online" /> } },
    { id: "mon", header: "Beobachtet", accessorFn: (r) => r.Monitored, meta: { align: "right" } },
    { id: "down", header: "Ausgefallen", accessorFn: (r) => r.Down, meta: { align: "right" }, cell: ({ getValue }) => <span className={Number(getValue()) > 0 ? "text-destructive font-semibold" : ""}>{String(getValue())}</span> },
    { id: "devices", header: "Geräte", accessorFn: (r) => r.Devices, meta: { align: "right" } },
    { id: "last", header: "Zuletzt", accessorFn: (r) => r.Last?.occurred_at ?? "", cell: ({ row }) => row.original.Last ? <span className="text-muted-foreground"><span className="font-mono text-xs">{fmtTime(row.original.Last.occurred_at)}</span> {row.original.Last.Title}</span> : "–" },
  ]
  if (!d) return <Skeleton className="h-64" />
  return (
    <>
      <PageHeader crumbs={[{ label: "Kunden", to: "/tenants" }, { label: d.tenant.Name }]} title={d.tenant.Name} sub={<span className="font-mono">{d.tenant.ID}</span>}
        actions={<>
          <PinButton kind="tenant" id={d.tenant.ID} me={me.data} />
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild><Button size="sm"><Plus />Standort anlegen</Button></DialogTrigger>
            <DialogContent>
              <DialogHeader><DialogTitle>Neuer Standort</DialogTitle><DialogDescription>Je Standort eine Box. Die Box wird nach dem Enrollment hier zugeordnet.</DialogDescription></DialogHeader>
              <div className="grid gap-4">
                <div className="grid gap-2"><Label htmlFor="sslug">Kürzel</Label><Input id="sslug" value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="geschaeftsstelle" /></div>
                <div className="grid gap-2"><Label htmlFor="sname">Name</Label><Input id="sname" value={name} onChange={(e) => setName(e.target.value)} placeholder="Geschäftsstelle" /></div>
              </div>
              <DialogFooter><Button variant="outline" onClick={() => setOpen(false)}>Abbrechen</Button><Button onClick={() => create.mutate()} disabled={!slug || !name || create.isPending}>Anlegen</Button></DialogFooter>
            </DialogContent>
          </Dialog>
        </>} />
      <section className="flex flex-wrap items-center gap-3 rounded-md border bg-card px-4 py-3 text-sm">
        <span className="font-medium">KI-Auswertung</span>
        <span className="text-muted-foreground">Was das Modell von diesem Kunden sehen darf. Aus: nichts verlässt den Server. Facts: Inventar, Dienste, Findings, Ereignisse, Konnektor-Facts, keine Zugangsdaten, keine Logs. Voraussetzung: Auftragsverarbeitung mit dem Anbieter und Zustimmung des Kunden.</span>
        <div className="ml-auto flex gap-2">
          <Button size="sm" variant={d.tenant.AIScope === "facts" ? "default" : "outline"} onClick={() => aiSet.mutate("facts")} disabled={aiSet.isPending || d.tenant.AIScope === "facts"}>Facts</Button>
          <Button size="sm" variant={d.tenant.AIScope !== "facts" ? "default" : "outline"} onClick={() => aiSet.mutate("off")} disabled={aiSet.isPending || d.tenant.AIScope !== "facts"}>Aus</Button>
        </div>
      </section>
      <PatchOrgCard tenantId={d.tenant.ID} tenantName={d.tenant.Name} />
      <section className="flex flex-col gap-3">
        <h2 className="text-base font-semibold">Standorte</h2>
        <DataTable columns={cols} data={d.sites ?? []} onRowClick={(r) => navigate(`/sites/${r.Site.ID}`)} rowClass={(r) => r.Down ? "border-l-2 border-l-destructive" : ""} emptyTitle="Noch kein Standort" emptyText="Oben rechts anlegen." />
      </section>
      <section className="flex flex-col gap-3">
        <h2 className="text-base font-semibold">Ereignisse der letzten 24 Stunden</h2>
        <EventList events={d.events ?? []} emptyText="In den letzten 24 Stunden hat sich bei diesem Kunden nichts geändert." footer={<Link className="underline" to={`/events?tenant=${d.tenant.ID}`}>Alle Ereignisse dieses Kunden</Link>} />
      </section>
    </>
  )
}
