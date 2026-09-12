import { useState } from "react"
import { Link } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ShieldBan } from "lucide-react"
import { toast } from "sonner"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Skeleton } from "@/components/ui/skeleton"
import { Ago } from "@/components/clock"
import { get, post, type SiteDNS } from "@/lib/api"

// The DNS sensor (ADR-0020): the box as the LAN's resolver, watching for known
// malicious domains, random-name storms and tunnels. Off until the router points
// at the box; the card says what to enter where.
export function DNSCard({ siteId }: { siteId: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["site-dns", siteId], queryFn: () => get<SiteDNS>(`/api/sites/${siteId}/dns`), refetchInterval: 30_000 })
  const [ups, setUps] = useState<string | null>(null)
  const m = useMutation({
    mutationFn: (form: Record<string, string>) => post(`/api/sites/${siteId}/dns`, form),
    onSuccess: (r) => { toast.success(r.message); setUps(null); qc.invalidateQueries({ queryKey: ["site-dns", siteId] }) },
    onError: (e) => toast.error(e.message),
  })
  const d = q.data
  if (!d) return <Skeleton className="h-48" />
  const r = d.report
  const upstreams = ups ?? d.upstreams.join(", ")
  const save = (enabled: boolean, block: boolean) => m.mutate({ enabled: enabled ? "1" : "0", block: block ? "1" : "0", upstreams })
  const today = d.days[0]
  const state = !d.enabled ? "aus" : r?.listening ? (d.block ? "an, blockt" : "an, meldet") : r?.error ? "Fehler" : "wartet auf die Box"
  const cls = !d.enabled ? "text-muted-foreground" : r?.error ? "border-destructive/40 text-destructive" : r?.listening ? "border-primary/40 text-primary" : "border-foreground/40"
  return (
    <Card className={d.findings > 0 ? "border-destructive/40" : ""}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><ShieldBan className="size-4" />DNS-Sensor<Badge variant="outline" className={cls}>{state}</Badge></CardTitle>
        <CardDescription>Die Box wird der Namensauflöser des LANs und sieht jede Anfrage, ohne sie zu speichern: bekannte Schad-Domains (abuse.ch URLhaus und ThreatFox, eigene Einträge), Geräte, die zufällige Namen erzeugen (Malware auf Serversuche), und DNS-Tunnel. Wahlweise blockt sie Schad-Domains. Dafür muss der Router die Box als DNS-Server verteilen; als zweiten Server den Router selbst eintragen, damit die Geräte ohne Box nicht ohne Namen dastehen.</CardDescription>
        <CardAction>
          <label className="flex items-center gap-2 text-sm"><span className="text-muted-foreground">{d.hasBox ? "Sensor" : "keine Box"}</span><Switch checked={d.enabled} disabled={!d.hasBox || m.isPending} onCheckedChange={(on) => save(on, d.block)} /></label>
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-2 text-sm">
        {d.reinstall && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2">
            <div className="font-medium">Installation der Box ist älter als diese Funktion</div>
            <p className="mt-1 text-muted-foreground">Der Agent hat sich aktualisiert, aber die Installation auf der Box darf Port 53 noch nicht öffnen (und auch die Köder 445 und 23 nicht). Einmalig auf der Box ausführen{d.boxSsh ? <> (per <span className="font-mono">{d.boxSsh}</span>)</> : null}; danach kommen solche Rechte mit jedem Update von selbst:</p>
            <pre className="mt-2 overflow-x-auto rounded bg-muted px-2 py-1 font-mono text-xs">{d.reinstall}</pre>
          </div>
        )}
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Im Router eintragen</span><span>{d.boxIp ? <>DNS-Server <span className="font-mono">{d.boxIp}</span> <span className="text-muted-foreground">(FRITZ!Box: Heimnetz → Netzwerk → Netzwerkeinstellungen → IPv4 → lokaler DNS-Server; FortiGate: DHCP-Server → DNS-Server)</span></> : <span className="text-muted-foreground">Adresse der Box noch nicht gemeldet</span>}</span></div>
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Box</span><span>{r ? <>{r.listening ? <>hört auf <span className="font-mono">{r.listening}</span></> : r.error ? <span className="text-destructive">{r.error}</span> : "nicht aktiv"}{r.upstream ? <> · fragt <span className="font-mono">{r.upstream}</span></> : null} · Liste {r.list_size} Domains{r.list_version && d.list.version && r.list_version !== d.list.version ? <span className="text-muted-foreground"> (Server hat eine neuere)</span> : null}{d.reportAt ? <span className="text-muted-foreground"> · <Ago t={d.reportAt} /></span> : null}</> : <span className="text-muted-foreground">noch kein Bericht{d.enabled ? "; die Box holt die Einstellung mit dem nächsten Heartbeat (Agent ab 0.7)" : ""}</span>}</span></div>
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Heute</span><span>{today ? <>{today.Queries} Anfragen · {today.Blocked} geblockt · {today.NXDomain} unbekannte Namen{today.Failed ? <span className="text-destructive"> · {today.Failed} ohne Antwort vom Upstream</span> : null}</> : "–"}</span></div>
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Findings</span><span>{d.findings > 0 ? <Link className="underline text-destructive" to="/findings">{d.findings} offen aus dem DNS-Sensor</Link> : "keine offenen"}</span></div>
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Blockliste</span><span>{d.listOff ? <span className="text-muted-foreground">auf diesem Server aus</span> : d.list.domains > 0 ? <>{d.list.domains} Domains, Stand <Ago t={d.list.fetchedAt} /> · <Link className="underline" to="/settings">eigene Domains</Link></> : <span className="text-muted-foreground">noch nicht geladen</span>}</span></div>
        <div className="mt-2 flex flex-wrap items-end gap-3 border-t pt-3">
          <label className="flex items-center gap-2"><Switch checked={d.block} disabled={!d.hasBox || m.isPending} onCheckedChange={(on) => save(d.enabled, on)} /><span>Schad-Domains blocken (NXDOMAIN) statt nur melden</span></label>
          <div className="grid gap-1"><Label htmlFor="dns-ups">Upstream-Resolver (leer = die der Box; bei Schleife über den Router z. B. 9.9.9.9)</Label><Input id="dns-ups" value={upstreams} onChange={(e) => setUps(e.target.value)} placeholder="9.9.9.9, 1.1.1.1" className="w-72 font-mono" /></div>
          <Button size="sm" variant="outline" onClick={() => save(d.enabled, d.block)} disabled={m.isPending || ups === null}>Upstream speichern</Button>
        </div>
      </CardContent>
    </Card>
  )
}
