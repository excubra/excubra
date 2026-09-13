import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Pause, Play, Plug, RefreshCw, ShieldCheck, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { Ago } from "@/components/clock"
import { SealFingerprint } from "@/components/seal-fingerprint"
import { MetricChart } from "@/components/metric-chart"
import { get, post, type ConnectorView, type DeviceConnectors, type KindOption } from "@/lib/api"
import { sealFor } from "@/lib/seal"
import { fmtDateTime } from "@/lib/format"

// The connector tab of a device: what the box reads through the device's API,
// and the dialog that seals a credential to the box before anything leaves the browser.
export function ConnectorPanel({ deviceId }: { deviceId: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["device-connectors", deviceId], queryFn: () => get<DeviceConnectors>(`/api/devices/${deviceId}/connectors`), refetchInterval: 30_000 })
  const d = q.data
  const refresh = () => { qc.invalidateQueries({ queryKey: ["device-connectors", deviceId] }); qc.invalidateQueries({ queryKey: ["me"] }) }
  const act = useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post(path, form),
    onSuccess: (r) => { toast.success(r.message); refresh() },
    onError: (e) => toast.error(e.message),
  })
  if (!d) return <Skeleton className="h-48" />
  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Plug className="size-4" />Konnektoren</CardTitle>
          <CardDescription>Die Box liest das Gerät über seine API. Zugangsdaten werden hier im Browser für genau diese Box versiegelt; der Server sieht sie nie, nur die Box kann sie öffnen.</CardDescription>
          <CardAction><ConnectDialog d={d} deviceId={deviceId} onDone={refresh} /></CardAction>
        </CardHeader>
        <CardContent className="grid gap-2 text-sm @2xl/main:grid-cols-2">
          <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Box</span><span>{d.box ? <>{d.box.Name || d.box.ID} <Badge variant="outline" className={d.online ? "border-primary/40 text-primary" : "border-destructive/40 text-destructive"}>{d.online ? "online" : "schweigt"}</Badge></> : <span className="text-destructive">keine Box am Standort</span>}</span></div>
          <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Siegelschlüssel</span><span><SealFingerprint sealKey={d.sealKey} /> <span className="text-xs text-muted-foreground">beim ersten Mal mit der Box vergleichen</span></span></div>
        </CardContent>
      </Card>
      {d.connectors.length === 0 && (
        <Empty className="border"><EmptyHeader><EmptyMedia variant="icon"><Plug /></EmptyMedia><EmptyTitle>Noch kein Konnektor</EmptyTitle><EmptyDescription>„Verbinden“ oben rechts: FortiGate mit API-Token, STARFACE mit Benutzer und Passwort. Die Box liest dann alle paar Minuten Status, Version, Lizenz und Zähler.</EmptyDescription></EmptyHeader></Empty>
      )}
      {d.connectors.map((c) => <ConnectorCard key={c.id} c={c} d={d} deviceId={deviceId} pending={act.isPending} onAct={(path, form) => act.mutate({ path, form })} onDone={refresh} />)}
    </div>
  )
}

const CLASS_LABEL: Record<ConnectorView["class"], { label: string; cls: string }> = {
  ok: { label: "liest", cls: "border-primary/40 text-primary" },
  failed: { label: "gestört", cls: "border-destructive/40 text-destructive" },
  paused: { label: "pausiert", cls: "text-muted-foreground" },
  pending: { label: "wartet auf erste Lesung", cls: "text-muted-foreground" },
}

const METRIC_LABEL: Record<string, (v: number) => string> = {
  cpu_pct: (v) => `CPU ${v} %`, mem_pct: (v) => `RAM ${v} %`, disk_pct: (v) => `Platte ${v} %`, sessions: (v) => `${v} Sessions`,
  interfaces_up: (v) => `${v} Interfaces up`, interfaces_down: (v) => `${v} down`, ipsec_up: (v) => `${v} Tunnel up`, ipsec_down: (v) => `${v} Tunnel down`,
  ha_peers: (v) => `${v} HA-Partner`, licenses_expired: (v) => `${v} Lizenzen abgelaufen`, users: (v) => `${v} Benutzer`, phonenumbers: (v) => `${v} Rufnummern`,
}

function ConnectorCard({ c, d, deviceId, pending, onAct, onDone }: { c: ConnectorView; d: DeviceConnectors; deviceId: string; pending: boolean; onAct: (path: string, form?: Record<string, string>) => void; onDone: () => void }) {
  const st = CLASS_LABEL[c.class]
  const metrics = Object.entries(c.metrics).filter(([k]) => METRIC_LABEL[k]).sort(([a], [b]) => a.localeCompare(b))
  return (
    <Card className={c.class === "failed" ? "border-destructive/40" : ""}>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">{c.kindLabel}<span className="font-mono text-sm font-normal text-muted-foreground">{c.url}</span><Badge variant="outline" className={st.cls}>{st.label}</Badge></CardTitle>
        <CardDescription>
          {c.lastAt ? <>zuletzt gelesen <Ago t={c.lastAt} /> · alle {Math.round(c.intervalS / 60)} min</> : `alle ${Math.round(c.intervalS / 60)} min, sobald die Box die Zugangsdaten hat`}
          {" · "}versiegelt von {c.sealedBy || "?"} am {fmtDateTime(c.sealedAt)}
          {c.tlsFingerprint ? " · Zertifikat festgenagelt" : c.seenFingerprint ? " · Zertifikat nicht festgenagelt" : ""}
        </CardDescription>
        <CardAction className="flex flex-wrap gap-2">
          {!c.tlsFingerprint && c.seenFingerprint && <Button size="sm" variant="outline" title={c.seenFingerprint} onClick={() => onAct(`/api/connectors/${c.id}/pin`)} disabled={pending}><ShieldCheck />Zertifikat festnageln</Button>}
          <ConnectDialog d={d} deviceId={deviceId} onDone={onDone} existing={c} />
          <Button size="sm" variant="outline" onClick={() => onAct(`/api/connectors/${c.id}/toggle`)} disabled={pending}>{c.disabled ? <><Play />Fortsetzen</> : <><Pause />Pausieren</>}</Button>
          <AlertDialog>
            <AlertDialogTrigger asChild><Button size="sm" variant="outline" className="text-destructive"><Trash2 />Entfernen</Button></AlertDialogTrigger>
            <AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Konnektor entfernen?</AlertDialogTitle><AlertDialogDescription>Die versiegelten Zugangsdaten werden gelöscht, die Box hört auf, das Gerät zu lesen. Gesammelte Messwerte bleiben in den Tagesdatenbanken.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Abbrechen</AlertDialogCancel><AlertDialogAction onClick={() => onAct(`/api/connectors/${c.id}/delete`)}>Entfernen</AlertDialogAction></AlertDialogFooter></AlertDialogContent>
          </AlertDialog>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {c.class === "failed" && <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm"><span className="font-medium text-destructive">Lesung fehlgeschlagen:</span> {c.lastError}</div>}
        {metrics.length > 0 && <div className="flex flex-wrap gap-2">{metrics.map(([k, v]) => <Badge key={k} variant="secondary" className="font-mono text-xs">{METRIC_LABEL[k](v)}</Badge>)}</div>}
        {metrics.length > 0 && <MetricChart connectorId={c.id} metrics={c.metrics} />}
        <FactsView facts={c.facts} />
      </CardContent>
    </Card>
  )
}

const FACT_LABEL: Record<string, string> = {
  serial: "Seriennummer", version: "Firmware", build: "Build", hostname: "Hostname", model: "Modell", log_disk: "Log-Platte", ha_mode: "HA-Modus", ha_group: "HA-Gruppe", ha_peers: "HA-Partner",
  interfaces: "Interfaces", ipsec: "IPsec-Tunnel", licenses: "Lizenzen", admin_https_port: "Admin-HTTPS-Port", admin_ssh_port: "Admin-SSH-Port", admin_timeout_min: "Admin-Timeout (min)", timezone: "Zeitzone",
  login: "Anmeldung", state: "Zustand", problems: "Nicht lesbar",
}
const label = (k: string) => FACT_LABEL[k] ?? k.replace(/_/g, " ")

// FactsView renders whatever the device said: scalars as rows, lists of objects as
// tables, objects as nested rows. Problems (endpoints the reader could not use) go last.
export function FactsView({ facts }: { facts: Record<string, unknown> }) {
  const entries = Object.entries(facts ?? {}).filter(([k]) => !k.startsWith("_") && k !== "problems")
  const problems = Array.isArray(facts?.problems) ? (facts.problems as string[]) : []
  if (entries.length === 0 && problems.length === 0) return <p className="text-sm text-muted-foreground">Noch keine Facts. Die erste Lesung kommt mit dem nächsten Heartbeat nach dem Config-Pull.</p>
  const scalars = entries.filter(([, v]) => v === null || typeof v !== "object")
  const complex = entries.filter(([, v]) => v !== null && typeof v === "object")
  return (
    <div className="flex flex-col gap-4">
      {scalars.length > 0 && (
        <dl className="grid gap-x-6 gap-y-1 text-sm @2xl/main:grid-cols-2 @5xl/main:grid-cols-3">
          {scalars.map(([k, v]) => <div key={k} className="grid grid-cols-[150px_1fr] gap-3"><dt className="truncate text-muted-foreground">{label(k)}</dt><dd className="font-mono text-[13px] break-all">{String(v)}</dd></div>)}
        </dl>
      )}
      {complex.map(([k, v]) => (
        <div key={k}>
          <div className="mb-1 text-sm font-medium">{label(k)}</div>
          <Complex value={v} />
        </div>
      ))}
      {problems.length > 0 && <div className="text-xs text-muted-foreground"><span className="font-medium">Nicht lesbar:</span> {problems.join(" · ")}</div>}
    </div>
  )
}

function Complex({ value }: { value: unknown }) {
  if (Array.isArray(value)) {
    if (value.length === 0) return <p className="text-sm text-muted-foreground">keine</p>
    if (typeof value[0] === "object" && value[0] !== null) {
      const cols = Array.from(new Set(value.flatMap((r) => Object.keys(r as object)))).filter((c) => !c.startsWith("_")).slice(0, 8)
      return (
        <div className="overflow-x-auto rounded-xl border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left text-xs text-muted-foreground"><tr>{cols.map((c) => <th key={c} className="px-2 py-1.5 font-medium">{label(c)}</th>)}</tr></thead>
            <tbody>{value.map((r, i) => <tr key={i} className="border-t">{cols.map((c) => <td key={c} className="px-2 py-1.5 font-mono text-xs"><Cell v={(r as Record<string, unknown>)[c]} k={c} /></td>)}</tr>)}</tbody>
          </table>
        </div>
      )
    }
    return <div className="font-mono text-xs">{value.map(String).join(", ")}</div>
  }
  if (value && typeof value === "object") {
    const es = Object.entries(value as Record<string, unknown>)
    return (
      <dl className="grid gap-x-6 gap-y-1 text-sm @2xl/main:grid-cols-2 @5xl/main:grid-cols-3">
        {es.map(([k, v]) => <div key={k} className="grid grid-cols-[150px_1fr] gap-3"><dt className="truncate text-muted-foreground">{label(k)}</dt><dd className="font-mono text-[13px] break-all"><Cell v={v} k={k} /></dd></div>)}
      </dl>
    )
  }
  return <span className="font-mono text-xs">{String(value)}</span>
}

// epochDate turns a unix timestamp (seconds) into a readable date; other numbers stay.
function epochDate(k: string, v: unknown): string | null {
  if (typeof v !== "number" || !/expires|_at$|since/.test(k) || v < 1e9 || v > 4e9) return null
  return fmtDateTime(new Date(v * 1000).toISOString())
}

function Cell({ v, k }: { v: unknown; k?: string }) {
  if (v === null || v === undefined) return <span className="text-muted-foreground">–</span>
  if (k) { const d = epochDate(k, v); if (d) return <span>{d}</span> }
  if (typeof v === "boolean") return <Badge variant="outline" className={v ? "border-primary/40 text-primary" : "border-destructive/40 text-destructive"}>{v ? "ja" : "nein"}</Badge>
  if (typeof v === "object") {
    if (Array.isArray(v)) return <span>{v.map((x) => (typeof x === "object" && x !== null ? Object.values(x as object).map(String).join("/") : String(x))).join(", ")}</span>
    return <span>{Object.entries(v as Record<string, unknown>).map(([k, x]) => `${label(k)}: ${epochDate(k, x) ?? String(x)}`).join(", ")}</span>
  }
  const s = String(v)
  if (/^(up|ok|registered|licensed|valid)$/i.test(s)) return <span className="text-primary">{s}</span>
  if (/^(down|expired|error|failed)$/i.test(s)) return <span className="text-destructive">{s}</span>
  return <span>{s}</span>
}

// ConnectDialog seals the credential in the browser and posts only the ciphertext.
function ConnectDialog({ d, deviceId, onDone, existing }: { d: DeviceConnectors; deviceId: string; onDone: () => void; existing?: ConnectorView }) {
  const [open, setOpen] = useState(false)
  const [kind, setKind] = useState(existing?.kind ?? d.kinds[0]?.kind ?? "fortigate")
  const [url, setUrl] = useState(existing?.url ?? "")
  const [fields, setFields] = useState<Record<string, string>>({})
  const [interval, setInterval] = useState(String(existing?.intervalS ?? 300))
  const [pin, setPin] = useState(existing?.tlsFingerprint ?? "")
  const [busy, setBusy] = useState(false)
  const [mode, setMode] = useState("")
  const opt: KindOption | undefined = d.kinds.find((k) => k.kind === kind)
  const modes = opt?.modes ?? []
  const activeMode = modes.find((m) => m.id === mode) ?? modes[0]
  const credFields = activeMode ? activeMode.fields : (opt?.fields ?? [])
  const canSeal = !!d.sealKey && !!d.box
  const submit = async () => {
    setBusy(true)
    try {
      const form: Record<string, string> = { kind, url, interval_s: interval, tls_fingerprint: pin }
      const filled = credFields.filter((f) => (fields[f] ?? "").trim() !== "")
      if (!existing && filled.length !== credFields.length) throw new Error("Zugangsdaten unvollständig.")
      if (filled.length > 0) {
        if (filled.length !== credFields.length) throw new Error("Zugangsdaten unvollständig; entweder alle Felder oder keins.")
        const cred: Record<string, string> = {}
        for (const f of credFields) cred[f] = fields[f].trim()
        form.sealed = await sealFor(d.sealKey, JSON.stringify(cred))
      }
      const r = await post(existing ? `/api/connectors/${existing.id}/secret` : `/api/devices/${deviceId}/connectors`, form)
      toast.success(r.message)
      setOpen(false); setFields({})
      onDone()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  const fieldLabel: Record<string, string> = { token: "API-Token", user: "Benutzer", password: "Passwort", admin_user: "Administrator", admin_password: "Administrator-Passwort" }
  return (
    <>
      <Button size="sm" variant={existing ? "outline" : "default"} onClick={() => setOpen(true)} disabled={!canSeal} title={canSeal ? "" : "Die Box hat noch keinen Siegelschlüssel gemeldet"}>{existing ? <><RefreshCw />Zugangsdaten erneuern</> : <><Plug />Verbinden</>}</Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{existing ? `${existing.kindLabel} · Zugangsdaten erneuern` : "Gerät über seine API verbinden"}</DialogTitle>
            <DialogDescription>Die Zugangsdaten werden in diesem Browser für die Box <span className="font-mono">{d.box?.Name || d.box?.ID}</span> versiegelt (Siegelschlüssel <SealFingerprint sealKey={d.sealKey} />). Der Server speichert nur das Chiffrat.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4">
            {!existing && (
              <div className="grid gap-2"><Label>Art</Label>
                <Select value={kind} onValueChange={setKind}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{d.kinds.map((k) => <SelectItem key={k.kind} value={k.kind}>{k.label}</SelectItem>)}</SelectContent></Select>
              </div>
            )}
            {modes.length > 0 && (
              <div className="grid gap-2"><Label>Zugang</Label>
                <Select value={activeMode?.id ?? ""} onValueChange={(v) => { setMode(v); setFields({}) }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{modes.map((m) => <SelectItem key={m.id} value={m.id}>{m.label}</SelectItem>)}</SelectContent></Select>
                {activeMode && <span className="text-xs text-muted-foreground">{activeMode.hint}</span>}
              </div>
            )}
            <div className="grid gap-2"><Label>Adresse der API</Label><Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder={kind === "starface" ? "https://starface.kunde.local" : "https://192.168.1.1"} className="font-mono" /><span className="text-xs text-muted-foreground">Nur Schema und Host, wie die Box das Gerät im LAN erreicht.</span></div>
            {credFields.map((f) => (
              <div key={f} className="grid gap-2"><Label>{fieldLabel[f] ?? f}{existing ? " (leer lassen = unverändert)" : ""}</Label><Input type={f === "token" || f.endsWith("password") ? "password" : "text"} autoComplete="off" value={fields[f] ?? ""} onChange={(e) => setFields({ ...fields, [f]: e.target.value })} className="font-mono" /></div>
            ))}
            {kind === "starface" && !existing && <p className="text-xs text-muted-foreground">STARFACE: ein Benutzer mit Administratorrecht; ab Version 10 wird OAuth 2.0 (rest-client-headless) benutzt, davor die klassische Anmeldung.</p>}
            <div className="grid gap-4 @md/main:grid-cols-2">
              <div className="grid gap-2"><Label>Lesetakt</Label>
                <Select value={interval} onValueChange={setInterval}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="60">jede Minute</SelectItem><SelectItem value="300">alle 5 Minuten</SelectItem><SelectItem value="900">alle 15 Minuten</SelectItem><SelectItem value="3600">jede Stunde</SelectItem></SelectContent></Select>
              </div>
              <div className="grid gap-2"><Label>Zertifikat (SHA-256, optional)</Label><Input value={pin} onChange={(e) => setPin(e.target.value)} placeholder="leer = beim ersten Lesen merken" className="font-mono" /></div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>Abbrechen</Button>
            <Button onClick={submit} disabled={busy || !url}>{busy ? "Versiegle …" : existing ? "Speichern" : "Versiegeln und verbinden"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
