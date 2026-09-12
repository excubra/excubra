import { Link } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Globe, Radar } from "lucide-react"
import { toast } from "sonner"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Skeleton } from "@/components/ui/skeleton"
import { Ago } from "@/components/clock"
import { get, post, type SiteScan } from "@/lib/api"

// The site's service scan (ADR-0018): the switch, when the box last looked, and
// what it found. The box scans on its own schedule; nothing here triggers a round.
export function ScanCard({ siteId }: { siteId: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["site-scan", siteId], queryFn: () => get<SiteScan>(`/api/sites/${siteId}/scan`), refetchInterval: 30_000 })
  const m = useMutation({
    mutationFn: (enabled: boolean) => post(`/api/sites/${siteId}/scan`, { enabled: enabled ? "1" : "0" }),
    onSuccess: (r) => { toast.success(r.message); qc.invalidateQueries({ queryKey: ["site-scan", siteId] }) },
    onError: (e) => toast.error(e.message),
  })
  const d = q.data
  if (!d) return <Skeleton className="h-36" />
  const last = d.last
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Radar className="size-4" />Schwachstellen-Scan<Badge variant="outline" className={d.enabled ? "border-primary/40 text-primary" : "text-muted-foreground"}>{d.enabled ? "an" : "aus"}</Badge></CardTitle>
        <CardDescription>Die Box tastet die Geräte dieses Standorts täglich ab, der Außenposten die öffentliche Adresse stündlich: welche Dienste laufen, welche Version, welches Zertifikat. Gedrosselt, nach Zeitplan, nichts wird ausgenutzt, keine Zugangsdaten probiert. Was auffällt, steht unter Prävention.</CardDescription>
        <CardAction>
          <label className="flex items-center gap-2 text-sm"><span className="text-muted-foreground">{d.hasBox ? "Scan" : "keine Box"}</span><Switch checked={d.enabled} disabled={!d.hasBox || m.isPending} onCheckedChange={(on) => m.mutate(on)} /></label>
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-1 text-sm">
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Letzte Runde</span><span>{last ? <>{last.FinishedAt ? <>abgeschlossen <Ago t={last.FinishedAt} /></> : <>läuft, begonnen <Ago t={last.StartedAt} /></>} · {last.Hosts} Geräte, {last.Services} Dienste{last.Errors ? `, ${last.Errors} Fehler` : ""}</> : d.enabled ? "noch keine; die erste beginnt wenige Minuten nach dem Einschalten" : "–"}</span></div>
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Dienste</span><span>{d.services} offen auf {d.devices} Geräten</span></div>
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Findings</span><span>{d.findings > 0 ? <Link className="underline" to="/findings">{d.findings} offen aus dem Scan</Link> : "keine offenen aus dem Scan"}</span></div>
        {d.wan && (
          <div className="mt-3 border-t pt-3">
            <div className="mb-1 flex items-center gap-2 font-medium"><Globe className="size-4" />Außenansicht<span className="font-mono text-xs text-muted-foreground">{d.wan.ip || "Adresse noch unbekannt"}</span></div>
            <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Zuletzt geprüft</span><span>{d.wan.last ? <><Ago t={d.wan.last.StartedAt} /> vom Außenposten, {d.wan.last.Services} offene Ports</> : d.wan.outpost ? (d.enabled ? "noch nicht; der Außenposten schaut stündlich" : "erst, wenn der Scan an ist") : "kein Außenposten eingerichtet"}</span></div>
            <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Von außen offen</span><span>{d.wan.deviceId ? <Link className="underline" to={`/devices/${d.wan.deviceId}?tab=dienste`}>{d.wan.services} Dienste</Link> : `${d.wan.services} Dienste`}{d.wan.findings > 0 ? <> · <Link className="underline text-destructive" to="/findings">{d.wan.findings} Findings</Link></> : ""}</span></div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
