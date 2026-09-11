import { useState } from "react"
import { Link } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { Download } from "lucide-react"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { StatCard, StatGrid } from "@/components/stat-card"
import { DataTable } from "@/components/data-table"
import { Ago } from "@/components/clock"
import { LiveDot } from "@/components/status"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { get, post, type Release, type UpdateRow, type UpdatesData } from "@/lib/api"
import { fmtDateTime, fmtShort } from "@/lib/format"

const NONE = "__none"

export default function UpdatesPage() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["updates"], queryFn: () => get<UpdatesData>("/api/updates"), refetchInterval: 30_000 })
  const d = q.data
  const refresh = () => { qc.invalidateQueries({ queryKey: ["updates"] }); qc.invalidateQueries({ queryKey: ["me"] }) }
  const act = useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post(path, form),
    onSuccess: (r) => { toast.success(r.message); refresh() },
    onError: (e) => toast.error(e.message),
  })
  const cols: ColumnDef<UpdateRow, unknown>[] = [
    { id: "box", header: "Box", accessorFn: (r) => r.Name || r.ID, cell: ({ row }) => <div className="flex items-center gap-2"><LiveDot ok={row.original.State.Status !== "silent"} /><div><Link to={`/boxes/${row.original.ID}`} className="font-medium hover:underline">{row.original.Name || row.original.ID}</Link><div className="text-xs text-muted-foreground">{row.original.Assigned ? `${row.original.TenantName} · ${row.original.SiteName}` : "nicht zugeordnet"}</div></div></div> },
    { id: "version", header: "Version", accessorFn: (r) => r.AgentVersion, cell: ({ row }) => <div className="flex items-center gap-2 font-mono text-sm">{row.original.AgentVersion || "—"}{row.original.Target === "" ? <Badge variant="secondary">kein Ziel</Badge> : row.original.Behind ? <Badge variant="outline" className="border-destructive/40 text-destructive">veraltet → {row.original.Target}</Badge> : <Badge variant="outline" className="border-primary/40 text-primary">aktuell</Badge>}</div> },
    { id: "channel", header: "Kanal", accessorFn: (r) => r.Channel, cell: ({ row }) => <ChannelSelect value={row.original.Channel || "stable"} onChange={(c) => act.mutate({ path: `/api/boxes/${row.original.ID}/channel`, form: { channel: c } })} /> },
    { id: "os", header: "System", accessorFn: (r) => `${r.OS}/${r.Arch}`, cell: ({ getValue }) => <span className="font-mono text-xs text-muted-foreground">{String(getValue())}</span> },
    { id: "seen", header: "Gesehen", accessorFn: (r) => r.LastSeen, cell: ({ row }) => <Ago t={row.original.LastSeen} /> },
    { id: "note", header: "Letzte Meldung", accessorFn: (r) => r.LastNote?.Text ?? "", cell: ({ row }) => row.original.LastNote ? <div className="max-w-[18rem] truncate text-sm" title={row.original.LastNote.Text}><span className="font-mono text-xs text-muted-foreground">{fmtShort(row.original.LastNote.At)}</span> {row.original.LastNote.Text}</div> : <span className="text-muted-foreground">—</span> },
    { id: "act", header: "", enableSorting: false, meta: { align: "right" }, cell: ({ row }) => {
      const waiting = (row.original.Pending ?? []).find((t) => t.Kind === "update")
      return waiting ? <Badge variant="secondary">Update holen wartet <Ago t={waiting.IssuedAt} /></Badge> : <Button size="sm" variant="outline" onClick={() => act.mutate({ path: `/api/boxes/${row.original.ID}/tasks`, form: { kind: "update" } })} disabled={act.isPending}><Download />Update holen</Button>
    } },
  ]
  const relCols: ColumnDef<Release, unknown>[] = [
    { id: "v", header: "Version", accessorFn: (r) => r.Version, cell: ({ getValue }) => <span className="font-mono">{String(getValue())}</span> },
    { id: "os", header: "System", accessorFn: (r) => `${r.OS}/${r.Arch}`, cell: ({ getValue }) => <span className="font-mono text-xs text-muted-foreground">{String(getValue())}</span> },
    { id: "min", header: "Min. Agent", accessorFn: (r) => r.MinAgentVersion || "—", cell: ({ getValue }) => <span className="font-mono text-xs">{String(getValue())}</span> },
    { id: "url", header: "Quelle", accessorFn: (r) => r.URL, cell: ({ getValue }) => <span className="block max-w-[24rem] truncate font-mono text-xs text-muted-foreground" title={String(getValue())}>{String(getValue())}</span> },
    { id: "at", header: "Hinterlegt", accessorFn: (r) => r.CreatedAt, cell: ({ getValue }) => fmtDateTime(String(getValue())) },
  ]
  return (
    <>
      <PageHeader crumbs={[{ label: "Updates" }]} title="Updates" sub="Jede Box holt sich signierte Releases selbst; hier steht, welche Version ein Kanal anbietet und wer noch hinterherhinkt." />
      {d ? (
        <StatGrid>
          <StatCard label="Auf Stand" value={d.Current} tone={d.Behind === 0 && d.Current > 0 ? "ok" : undefined} line1={`${d.Current} von ${(d.Boxes ?? []).length} Boxen laufen die Version ihres Kanals`} line2="Boxen prüfen einmal täglich von selbst" />
          <StatCard label="Veraltet" value={d.Behind} tone={d.Behind > 0 ? "bad" : "ok"} line1={d.Behind ? "Kanal zeigt auf eine neuere Version" : "Keine Box hinkt hinterher"} line2="„Update holen“ stößt die Prüfung sofort an" />
          <StatCard label="Ohne Ziel" value={d.NoTarget} line1={d.NoTarget ? "Kanal ohne Release" : "Jeder Kanal zeigt auf ein Release"} line2="Unten je Kanal eine Version wählen" />
          <StatCard label="Releases" value={(d.Releases ?? []).length} line1={`${(d.Versions ?? []).length} Versionen hinterlegt`} line2="Nur signierte Releases, der Server hält keine Binaries" />
        </StatGrid>
      ) : <Skeleton className="h-32" />}
      {d && (
        <div className="grid gap-4 @4xl/main:grid-cols-2">
          {(["stable", "canary"] as const).map((ch) => (
            <ChannelCard key={ch} channel={ch} current={d.Channels[ch] ?? ""} versions={d.Versions ?? []} boxes={(d.Boxes ?? []).filter((b) => (b.Channel || "stable") === ch).length} pending={act.isPending}
              onSet={(v) => act.mutate({ path: "/api/updates/channel", form: { channel: ch, version: v } })}
              onRollout={() => act.mutate({ path: "/api/updates/rollout", form: { channel: ch } })} />
          ))}
        </div>
      )}
      {d && <DataTable columns={cols} data={d.Boxes ?? []} search={(r) => `${r.Name} ${r.ID} ${r.TenantName} ${r.SiteName} ${r.AgentVersion}`} searchPlaceholder="Box, Kunde oder Version" rowClass={(r) => r.Behind ? "border-l-2 border-l-destructive" : ""} emptyTitle="Noch keine Box" emptyText="Sobald eine Box eingeschrieben ist, steht sie hier mit ihrer Version." />}
      {d && (
        <Card>
          <CardHeader><CardTitle>Hinterlegte Releases</CardTitle><CardDescription>Metadaten aus der Release-Pipeline: Version, Prüfsumme, Signatur und wo das Binary liegt. Hinterlegen auf dem Server: <code className="font-mono text-xs">excubra server release add …</code></CardDescription></CardHeader>
          <CardContent><DataTable columns={relCols} data={d.Releases ?? []} pageSize={10} emptyTitle="Noch kein Release hinterlegt" emptyText="Ohne Release bietet der Server keiner Box ein Update an. Die Boxen laufen trotzdem weiter." /></CardContent>
        </Card>
      )}
    </>
  )
}

function ChannelSelect({ value, onChange }: { value: string; onChange: (c: string) => void }) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger size="sm" className="w-28"><SelectValue /></SelectTrigger>
      <SelectContent><SelectItem value="stable">stable</SelectItem><SelectItem value="canary">canary</SelectItem></SelectContent>
    </Select>
  )
}

function ChannelCard({ channel, current, versions, boxes, pending, onSet, onRollout }: { channel: string; current: string; versions: string[]; boxes: number; pending: boolean; onSet: (v: string) => void; onRollout: () => void }) {
  const [v, setV] = useState(current || NONE)
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">Kanal <span className="font-mono">{channel}</span><Badge variant="secondary">{boxes} Box{boxes === 1 ? "" : "en"}</Badge></CardTitle>
        <CardDescription>{channel === "canary" ? "Erst VIICO, dann fünf Kundenboxen, dann der Rest: was hier steht, bekommt die Vorhut." : "Alle Boxen ohne besondere Einstellung."}{current ? ` Zeigt auf ${current}.` : " Zeigt auf keine Version."}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-2">
        <Select value={v} onValueChange={setV}>
          <SelectTrigger className="w-56"><SelectValue placeholder="Version" /></SelectTrigger>
          <SelectContent><SelectItem value={NONE}>— keine Version —</SelectItem>{versions.map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent>
        </Select>
        <Button size="sm" onClick={() => onSet(v === NONE ? "" : v)} disabled={pending || v === (current || NONE)}>Kanal setzen</Button>
        <Button size="sm" variant="outline" onClick={onRollout} disabled={pending || !current || boxes === 0}><Download />Alle {boxes} Boxen jetzt holen lassen</Button>
      </CardContent>
    </Card>
  )
}
