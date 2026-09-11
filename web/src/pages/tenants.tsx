import { useState } from "react"
import { useNavigate } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { Plus } from "lucide-react"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { StateBadge } from "@/components/status"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { get, post, type TenantRow } from "@/lib/api"

export default function TenantsPage() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["tenants"], queryFn: () => get<TenantRow[]>("/api/tenants") })
  const [open, setOpen] = useState(false)
  const [slug, setSlug] = useState("")
  const [name, setName] = useState("")
  const create = useMutation({
    mutationFn: () => post("/api/tenants", { slug, name }),
    onSuccess: (r) => { toast.success(r.message); setOpen(false); setSlug(""); setName(""); qc.invalidateQueries({ queryKey: ["tenants"] }); qc.invalidateQueries({ queryKey: ["me"] }) },
    onError: (e) => toast.error(e.message),
  })
  const cols: ColumnDef<TenantRow, unknown>[] = [
    { id: "name", header: "Kunde", accessorFn: (r) => r.Name, cell: ({ row }) => <div><div className="font-medium">{row.original.Name}</div><div className="font-mono text-xs text-muted-foreground">{row.original.ID}</div></div> },
    { id: "state", header: "Zustand", accessorFn: (r) => r.attention, cell: ({ row }) => { const r = row.original; return r.attention ? <StateBadge cls="down" label={`${r.attention} Störung${r.attention === 1 ? "" : "en"}`} /> : r.boxes ? <StateBadge cls="ok" label="alles online" /> : <Badge variant="secondary">keine Box</Badge> } },
    { id: "sites", header: "Standorte", accessorFn: (r) => r.sites, meta: { align: "right" } },
    { id: "boxes", header: "Boxen online", accessorFn: (r) => r.boxesOnline, meta: { align: "right" }, cell: ({ row }) => <span className={row.original.boxesOnline < row.original.boxes ? "text-destructive font-semibold" : ""}>{row.original.boxesOnline} / {row.original.boxes}</span> },
    { id: "hosts", header: "Beobachtet", accessorFn: (r) => r.hosts, meta: { align: "right" } },
    { id: "down", header: "Ausgefallen", accessorFn: (r) => r.down, meta: { align: "right" }, cell: ({ getValue }) => <span className={Number(getValue()) > 0 ? "text-destructive font-semibold" : ""}>{String(getValue())}</span> },
    { id: "devices", header: "Geräte", accessorFn: (r) => r.devices, meta: { align: "right" } },
  ]
  return (
    <>
      <PageHeader crumbs={[{ label: "Kunden" }]} title="Kunden" sub="Ein Kunde, ein oder mehrere Standorte, je Standort eine Box. Sortiert nach dem, was Aufmerksamkeit braucht."
        actions={
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild><Button size="sm"><Plus />Kunde anlegen</Button></DialogTrigger>
            <DialogContent>
              <DialogHeader><DialogTitle>Neuer Kunde</DialogTitle><DialogDescription>Das Kürzel wird Teil der Kennung (ten_kürzel) und taucht in Webhooks und der API auf.</DialogDescription></DialogHeader>
              <div className="grid gap-4">
                <div className="grid gap-2"><Label htmlFor="slug">Kürzel</Label><Input id="slug" value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="kundea" pattern="[a-z0-9-]{1,40}" /></div>
                <div className="grid gap-2"><Label htmlFor="name">Name</Label><Input id="name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Kunde A GmbH" /></div>
              </div>
              <DialogFooter><Button variant="outline" onClick={() => setOpen(false)}>Abbrechen</Button><Button onClick={() => create.mutate()} disabled={!slug || !name || create.isPending}>Anlegen</Button></DialogFooter>
            </DialogContent>
          </Dialog>
        } />
      <DataTable columns={cols} data={q.data ?? []} search={(r) => `${r.Name} ${r.ID}`} searchPlaceholder="Kunde suchen" onRowClick={(r) => navigate(`/tenants/${r.ID}`)} initialSort={[{ id: "state", desc: true }]} pageSize={50} emptyTitle="Noch kein Kunde" emptyText="Oben rechts den ersten anlegen." />
    </>
  )
}
