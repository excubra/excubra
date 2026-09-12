// The small administration pages share one shape: a table, a create dialog, row actions.
import { useState, type ReactNode } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { Copy, Plus } from "lucide-react"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { StateBadge } from "@/components/status"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Label } from "@/components/ui/label"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { get, post, type AuditRow, type KeyRow, type KeysData, type InstallerCommand, type MaintenanceWindow, type TokenRow, type UserRow, type WebhookRow } from "@/lib/api"
import { fmtDateTime, fmtShort } from "@/lib/format"

function useAct(keys: string[][]) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post<{ ok: boolean; message: string; to?: string; secrets?: string[]; commands?: { title: string; cmd: string }[]; token?: string; secret?: string }>(path, form),
    onSuccess: (r) => { toast.success(r.message); keys.forEach((k) => qc.invalidateQueries({ queryKey: k })) },
    onError: (e) => toast.error(e.message),
  })
}

function Secret({ label, value }: { label: string; value: string }) {
  return (
    <Alert className="border-primary/40">
      <AlertTitle>{label}</AlertTitle>
      <AlertDescription className="flex items-center gap-2"><code className="break-all rounded bg-muted px-2 py-1 text-xs">{value}</code><Button size="icon-xs" variant="ghost" onClick={() => { navigator.clipboard.writeText(value); toast.success("Kopiert") }}><Copy /></Button></AlertDescription>
    </Alert>
  )
}

type CreateField = { key: string; label: string; placeholder?: string; type?: string; def?: string; options?: { value: string; label: string }[] }
function CreateDialog({ title, description, fields, onSubmit, pending, trigger, submitLabel }: { title: string; description: string; fields: CreateField[]; onSubmit: (v: Record<string, string>) => void; pending: boolean; trigger: ReactNode; submitLabel?: string }) {
  const [open, setOpen] = useState(false)
  const [v, setV] = useState<Record<string, string>>(() => Object.fromEntries(fields.map((f) => [f.key, f.def ?? ""])))
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>{title}</DialogTitle><DialogDescription>{description}</DialogDescription></DialogHeader>
        <div className="grid gap-4">{fields.map((f) => <div key={f.key} className="grid gap-2"><Label htmlFor={f.key}>{f.label}</Label>{f.options ? (
          <Select value={v[f.key] || "__none"} onValueChange={(val) => setV({ ...v, [f.key]: val === "__none" ? "" : val })}>
            <SelectTrigger id={f.key}><SelectValue placeholder={f.placeholder} /></SelectTrigger>
            <SelectContent>{f.options.map((o) => <SelectItem key={o.value || "__none"} value={o.value || "__none"}>{o.label}</SelectItem>)}</SelectContent>
          </Select>
        ) : <Input id={f.key} type={f.type} value={v[f.key]} onChange={(e) => setV({ ...v, [f.key]: e.target.value })} placeholder={f.placeholder} />}</div>)}</div>
        <DialogFooter><Button variant="outline" onClick={() => setOpen(false)}>Abbrechen</Button><Button onClick={() => { onSubmit(v); setOpen(false) }} disabled={pending}>{submitLabel ?? "Anlegen"}</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- Enrollment-Keys --------------------------------------------------------------------

export function KeysPage() {
  const q = useQuery({ queryKey: ["keys"], queryFn: () => get<KeysData>("/api/keys") })
  const act = useAct([["keys"]])
  const [fresh, setFresh] = useState<string[]>([])
  const [cmds, setCmds] = useState<InstallerCommand[]>([])
  const siteOptions = [{ value: "", label: "kein Standort (Box später zuordnen)" }, ...(q.data?.sites ?? []).map((s) => ({ value: s.ID, label: s.Name }))]
  const cols: ColumnDef<KeyRow, unknown>[] = [
    { id: "id", header: "Key", accessorFn: (r) => r.id, cell: ({ getValue }) => <span className="font-mono text-xs">{String(getValue())}</span> },
    { id: "site", header: "Standort", accessorFn: (r) => r.siteName, cell: ({ getValue }) => getValue() ? <span>{String(getValue())}</span> : <span className="text-muted-foreground">–</span> },
    { id: "note", header: "Notiz", accessorFn: (r) => r.note },
    { id: "created", header: "Erstellt", accessorFn: (r) => r.createdAt, cell: ({ getValue }) => <span className="text-muted-foreground">{fmtShort(String(getValue()))}</span> },
    { id: "exp", header: "Gültig bis", accessorFn: (r) => r.expiresAt, cell: ({ getValue }) => <span className="text-muted-foreground">{fmtShort(String(getValue()))}</span> },
    { id: "state", header: "Zustand", accessorFn: (r) => (r.revokedAt ? "widerrufen" : r.usedAt ? "eingelöst" : new Date(r.expiresAt) < new Date() ? "abgelaufen" : "offen"), cell: ({ row, getValue }) => { const s = String(getValue()); return s === "eingelöst" ? <StateBadge cls="ok" label={`eingelöst · ${row.original.usedBy}`} /> : s === "offen" ? <Badge variant="outline">offen</Badge> : <Badge variant="secondary">{s}</Badge> } },
    { id: "act", header: "", enableSorting: false, cell: ({ row }) => (!row.original.usedAt && !row.original.revokedAt) ? <Button variant="ghost" size="xs" className="text-destructive" onClick={() => act.mutate({ path: `/api/keys/${row.original.id}/revoke` })}>Widerrufen</Button> : null },
  ]
  return (
    <>
      <PageHeader crumbs={[{ label: "Neue Box" }]} title="Neue Box" sub="Ein Key je Box, einmal gültig, mit Standort. Die Box meldet sich, ordnet sich selbst zu, tritt dem Techniker-Stack bei, ihr LAN wird freigeschaltet. Einen Befehl kopieren, fertig."
        actions={<CreateDialog title="Neue Box" description="Der Key wird genau einmal angezeigt, zusammen mit dem Befehl für den Proxmox-Host oder die Box selbst." submitLabel="Key erzeugen"
          fields={[{ key: "site_id", label: "Standort", options: siteOptions, placeholder: "Standort wählen" }, { key: "note", label: "Notiz (optional)", placeholder: "z. B. Lagergerät Nr. 3" }, { key: "expires_days", label: "Gültig (Tage)", type: "number", def: "30" }]}
          pending={act.isPending} trigger={<Button size="sm"><Plus />Neue Box</Button>}
          onSubmit={(v) => act.mutate({ path: "/api/keys", form: v }, { onSuccess: (r) => { setFresh(r.secrets ?? []); setCmds(r.commands ?? []) } })} />} />
      {fresh.map((s) => <Secret key={s} label="Enrollment-Key, einmalig sichtbar" value={s} />)}
      {cmds.map((c) => <Secret key={c.cmd} label={c.title} value={c.cmd} />)}
      <DataTable columns={cols} data={q.data?.keys ?? []} search={(r) => `${r.id} ${r.note} ${r.usedBy} ${r.siteName}`} initialSort={[{ id: "created", desc: true }]} emptyTitle="Noch kein Key" emptyText="„Neue Box“ erzeugt den Key und die Befehle." />
    </>
  )
}

// ---- API-Tokens -------------------------------------------------------------------------

export function TokensPage() {
  const q = useQuery({ queryKey: ["tokens"], queryFn: () => get<{ tokens: TokenRow[]; tenants: { ID: string; Name: string }[] | null }>("/api/tokens") })
  const act = useAct([["tokens"]])
  const [fresh, setFresh] = useState("")
  const cols: ColumnDef<TokenRow, unknown>[] = [
    { id: "name", header: "Name", accessorFn: (r) => r.name, cell: ({ row }) => <div><div className="font-medium">{row.original.name}</div><div className="font-mono text-xs text-muted-foreground">{row.original.id}</div></div> },
    { id: "tenants", header: "Mandanten", accessorFn: (r) => r.tenants.join(", "), cell: ({ getValue }) => <span className="font-mono text-xs">{String(getValue()) || "*"}</span> },
    { id: "created", header: "Erstellt", accessorFn: (r) => r.createdAt, cell: ({ getValue }) => <span className="text-muted-foreground">{fmtShort(String(getValue()))}</span> },
    { id: "used", header: "Zuletzt benutzt", accessorFn: (r) => r.lastUsed ?? "", cell: ({ getValue }) => <span className="text-muted-foreground">{getValue() ? fmtShort(String(getValue())) : "nie"}</span> },
    { id: "state", header: "Zustand", accessorFn: (r) => (r.revokedAt ? "widerrufen" : "aktiv"), cell: ({ getValue }) => String(getValue()) === "aktiv" ? <StateBadge cls="ok" label="aktiv" /> : <Badge variant="secondary">widerrufen</Badge> },
    { id: "act", header: "", enableSorting: false, cell: ({ row }) => !row.original.revokedAt ? <Button variant="ghost" size="xs" className="text-destructive" onClick={() => act.mutate({ path: `/api/tokens/${row.original.id}/revoke` })}>Widerrufen</Button> : null },
  ]
  return (
    <>
      <PageHeader crumbs={[{ label: "API-Tokens" }]} title="API-Tokens" sub="Lesezugriff auf die Status-API, nur im Overlay, je Token auf Mandanten beschränkbar."
        actions={<CreateDialog title="Neues Token" description="Das Token wird genau einmal angezeigt." fields={[{ key: "name", label: "Name", placeholder: "CRM-Dashboard" }, { key: "tenants", label: "Mandanten (Kennungen, Komma) oder *", def: "*" }]} pending={act.isPending} trigger={<Button size="sm"><Plus />Token erstellen</Button>}
          onSubmit={(v) => act.mutate({ path: "/api/tokens", form: v }, { onSuccess: (r) => setFresh(r.token ?? "") })} />} />
      {fresh && <Secret label="Neues Token, einmalig sichtbar" value={fresh} />}
      <DataTable columns={cols} data={q.data?.tokens ?? []} search={(r) => `${r.name} ${r.id}`} emptyTitle="Kein Token" emptyText="Für das CRM-Dashboard später ein Token nur für den passenden Mandanten anlegen." />
    </>
  )
}

// ---- Webhooks --------------------------------------------------------------------------

export function WebhooksPage() {
  const q = useQuery({ queryKey: ["webhooks"], queryFn: () => get<{ targets: WebhookRow[]; failed: unknown[] | null; tenants: { ID: string; Name: string }[] | null }>("/api/webhooks") })
  const act = useAct([["webhooks"]])
  const [fresh, setFresh] = useState("")
  const cols: ColumnDef<WebhookRow, unknown>[] = [
    { id: "name", header: "Ziel", accessorFn: (r) => r.name, cell: ({ row }) => <div><div className="font-medium">{row.original.name}</div><div className="font-mono text-xs text-muted-foreground">{row.original.url}</div></div> },
    { id: "state", header: "Zustand", accessorFn: (r) => (r.enabled ? "aktiv" : "aus"), cell: ({ getValue }) => String(getValue()) === "aktiv" ? <StateBadge cls="ok" label="aktiv" /> : <Badge variant="secondary">aus</Badge> },
    { id: "created", header: "Angelegt", accessorFn: (r) => r.createdAt, cell: ({ getValue }) => <span className="text-muted-foreground">{fmtShort(String(getValue()))}</span> },
    { id: "act", header: "", enableSorting: false, cell: ({ row }) => <div className="flex justify-end gap-1"><Button variant="ghost" size="xs" onClick={() => act.mutate({ path: `/api/webhooks/${row.original.id}/test`, form: { tenant_id: q.data?.tenants?.[0]?.ID ?? "" } })}>Test-Ereignis</Button><Button variant="ghost" size="xs" onClick={() => act.mutate({ path: `/api/webhooks/${row.original.id}`, form: { name: row.original.name, url: row.original.url, enabled: row.original.enabled ? "0" : "1" } })}>{row.original.enabled ? "Aus" : "An"}</Button><Button variant="ghost" size="xs" className="text-destructive" onClick={() => act.mutate({ path: `/api/webhooks/${row.original.id}/delete` })}>Löschen</Button></div> },
  ]
  return (
    <>
      <PageHeader crumbs={[{ label: "Webhooks" }]} title="Webhooks" sub="Jeder Zustandswechsel geht als signierte Nachricht ans CRM. Ohne Ziel wird gesammelt, nichts geht verloren."
        actions={<CreateDialog title="Neues Ziel" description="Signatur: sha256=HMAC(secret, ts.body), Wiederholung mit Backoff bis 24 h. Das Secret wird einmalig angezeigt." fields={[{ key: "name", label: "Name", placeholder: "CRM" }, { key: "url", label: "URL", placeholder: "https://crm.example/hook" }]} pending={act.isPending} trigger={<Button size="sm"><Plus />Ziel anlegen</Button>}
          onSubmit={(v) => act.mutate({ path: "/api/webhooks", form: v }, { onSuccess: (r) => setFresh(r.secret ?? "") })} />} />
      {fresh && <Secret label="Webhook-Secret, einmalig sichtbar" value={fresh} />}
      <DataTable columns={cols} data={q.data?.targets ?? []} emptyTitle="Kein Ziel eingerichtet" emptyText="Sobald das CRM eine Adresse hat, hier eintragen. Die Ereignisse warten so lange." />
    </>
  )
}

// ---- Benutzer, Audit, Wartung -------------------------------------------------------------

export function UsersPage() {
  const q = useQuery({ queryKey: ["users"], queryFn: () => get<UserRow[]>("/api/users") })
  const cols: ColumnDef<UserRow, unknown>[] = [
    { id: "name", header: "Name", accessorFn: (r) => r.name, cell: ({ row }) => <div><div className="font-medium">{row.original.name}</div><div className="font-mono text-xs text-muted-foreground">{row.original.id}</div></div> },
    { id: "totp", header: "Zweiter Faktor", accessorFn: (r) => r.totp, cell: ({ getValue }) => getValue() ? <StateBadge cls="ok" label="TOTP aktiv" /> : <StateBadge cls="bad" label="kein TOTP" /> },
    { id: "state", header: "Zustand", accessorFn: (r) => (r.disabled ? "deaktiviert" : r.locked ? "gesperrt" : "aktiv"), cell: ({ row, getValue }) => { const s = String(getValue()); return s === "aktiv" ? <StateBadge cls="ok" label="aktiv" /> : <StateBadge cls="bad" label={s === "gesperrt" ? `gesperrt bis ${fmtDateTime(row.original.lockedUntil)}` : s} /> } },
    { id: "failed", header: "Fehlversuche", accessorFn: (r) => r.failedLogins, meta: { align: "right" } },
    { id: "created", header: "Angelegt", accessorFn: (r) => r.createdAt, cell: ({ getValue }) => <span className="text-muted-foreground">{fmtDateTime(String(getValue()))}</span> },
  ]
  return (
    <>
      <PageHeader crumbs={[{ label: "Benutzer" }]} title="Benutzer" sub="Konsolen-Zugänge mit Passwort und zweitem Faktor. Anlegen und Passwort setzen geht nur per SSH auf dem Server, damit Geheimnisse nie durch die Konsole laufen." />
      <DataTable columns={cols} data={q.data ?? []} emptyTitle="Noch kein Benutzer" />
      <Alert><AlertTitle>Auf dem Server</AlertTitle><AlertDescription><pre className="mt-2 rounded bg-muted p-3 text-xs">excubra server user add &lt;name&gt;{"\n"}excubra server user passwd &lt;name&gt;{"\n"}excubra server user disable &lt;name&gt;</pre></AlertDescription></Alert>
    </>
  )
}

export function AuditPage() {
  const q = useQuery({ queryKey: ["audit"], queryFn: () => get<AuditRow[]>("/api/audit", { limit: "500" }) })
  const cols: ColumnDef<AuditRow, unknown>[] = [
    { id: "at", header: "Zeit", accessorFn: (r) => r.At, cell: ({ getValue }) => <span className="font-mono text-xs">{fmtDateTime(String(getValue()))}</span> },
    { id: "actor", header: "Wer", accessorFn: (r) => r.Actor },
    { id: "action", header: "Aktion", accessorFn: (r) => r.Action, cell: ({ getValue }) => <Badge variant="outline" className="font-mono">{String(getValue())}</Badge> },
    { id: "target", header: "Ziel", accessorFn: (r) => r.Target, cell: ({ getValue }) => <span className="font-mono text-xs">{String(getValue())}</span> },
    { id: "summary", header: "Details", accessorFn: (r) => r.Summary, cell: ({ getValue }) => <span className="text-muted-foreground">{String(getValue())}</span> },
  ]
  return (
    <>
      <PageHeader crumbs={[{ label: "Audit-Log" }]} title="Audit-Log" sub="Wer hat was geändert. Unveränderlich." />
      <DataTable columns={cols} data={q.data ?? []} search={(r) => `${r.Actor} ${r.Action} ${r.Target} ${r.Summary}`} pageSize={50} emptyTitle="Noch nichts passiert" />
    </>
  )
}

export function MaintenancePage() {
  const q = useQuery({ queryKey: ["maintenance"], queryFn: () => get<{ Windows: (MaintenanceWindow & { TargetName?: string })[] | null; Tenants: { ID: string; Name: string }[] | null; Sites: { ID: string; Name: string; TenantID: string }[] | null; Hosts: { ID: string; Name: string; Address: string }[] | null }>("/api/maintenance") })
  const act = useAct([["maintenance"], ["overview"]])
  const [scope, setScope] = useState("site")
  const [target, setTarget] = useState("")
  const [until, setUntil] = useState("")
  const [reason, setReason] = useState("")
  const cols: ColumnDef<MaintenanceWindow & { TargetName?: string }, unknown>[] = [
    { id: "scope", header: "Bereich", accessorFn: (r) => r.Scope, cell: ({ getValue }) => <Badge variant="secondary">{String(getValue())}</Badge> },
    { id: "target", header: "Ziel", accessorFn: (r) => r.TargetName ?? r.TargetID, cell: ({ row }) => <span>{row.original.TargetName ?? <span className="font-mono text-xs">{row.original.TargetID}</span>}</span> },
    { id: "until", header: "Bis", accessorFn: (r) => r.Until, cell: ({ getValue }) => fmtDateTime(String(getValue())) },
    { id: "reason", header: "Grund", accessorFn: (r) => r.Reason, cell: ({ getValue }) => <span className="text-muted-foreground">{String(getValue() || "–")}</span> },
    { id: "by", header: "Gesetzt von", accessorFn: (r) => r.SetBy, cell: ({ getValue }) => <span className="text-muted-foreground">{String(getValue() || "–")}</span> },
    { id: "act", header: "", enableSorting: false, cell: ({ row }) => <Button variant="ghost" size="xs" onClick={() => act.mutate({ path: `/api/maintenance/${row.original.ID}/end` })}>Beenden</Button> },
  ]
  const targets = scope === "tenant" ? (q.data?.Tenants ?? []).map((t) => ({ id: t.ID, label: t.Name })) : scope === "site" ? (q.data?.Sites ?? []).map((s) => ({ id: s.ID, label: s.Name })) : (q.data?.Hosts ?? []).map((h) => ({ id: h.ID, label: `${h.Name} (${h.Address})` }))
  return (
    <>
      <PageHeader crumbs={[{ label: "Wartung" }]} title="Wartung" sub="Ein Fenster unterdrückt Ereignisse für einen Kunden, Standort oder Host. Am Ende genau ein Übergang, falls sich etwas geändert hat." />
      <div className="grid gap-3 rounded-md border p-4 @3xl/main:grid-cols-[auto_1fr_auto_1fr_auto] @3xl/main:items-end">
        <div className="grid gap-2"><Label>Bereich</Label><select className="h-9 rounded-md border bg-transparent px-3 text-sm" value={scope} onChange={(e) => { setScope(e.target.value); setTarget("") }}><option value="tenant">Kunde</option><option value="site">Standort</option><option value="host">Host</option></select></div>
        <div className="grid gap-2"><Label>Ziel</Label><select className="h-9 rounded-md border bg-transparent px-3 text-sm" value={target} onChange={(e) => setTarget(e.target.value)}><option value="">wählen …</option>{targets.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}</select></div>
        <div className="grid gap-2"><Label>Bis</Label><Input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} /></div>
        <div className="grid gap-2"><Label>Grund</Label><Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="z. B. Proxmox-Update" /></div>
        <Button onClick={() => act.mutate({ path: "/api/maintenance", form: { scope, target_id: target, until, reason } })} disabled={!target || !until || act.isPending}>Fenster planen</Button>
      </div>
      <DataTable columns={cols} data={q.data?.Windows ?? []} emptyTitle="Kein Wartungsfenster geplant" emptyText="Beim nächsten Update beim Kunden zuerst hier ein Fenster anlegen, dann bleibt das CRM ruhig." />
    </>
  )
}
