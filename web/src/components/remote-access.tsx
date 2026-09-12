import { useState } from "react"
import { Link } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Waypoints, Power, PowerOff, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { Ago } from "@/components/clock"
import { get, post, type SiteRemote } from "@/lib/api"

// The switch that puts a site's LAN into the technicians' own overlay: the box
// becomes a second peer there and routes the LAN; EX0 wires the NetBird side.
export function RemoteAccessCard({ siteId }: { siteId: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["site-remote", siteId], queryFn: () => get<SiteRemote>(`/api/sites/${siteId}/remote`), refetchInterval: 15_000 })
  const d = q.data
  const [cidr, setCidr] = useState("")
  const refresh = () => qc.invalidateQueries({ queryKey: ["site-remote", siteId] })
  const m = useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post(path, form),
    onSuccess: (r) => { toast.success(r.message); refresh() },
    onError: (e) => toast.error(e.message),
  })
  if (!d) return <Skeleton className="h-40" />
  const a = d.access
  const state = a ? d.labels[a.State] ?? a.State : "nicht eingerichtet"
  const cls = !a ? "text-muted-foreground" : a.State === "active" ? "border-primary/40 text-primary" : a.State === "error" ? "border-destructive/40 text-destructive" : a.State === "off" ? "text-muted-foreground" : "border-foreground/40"
  const busy = a && (a.State === "key" || a.State === "joining" || a.State === "wiring")
  const value = cidr || a?.CIDR || d.suggested
  return (
    <Card className={a?.State === "error" ? "border-destructive/40" : ""}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Waypoints className="size-4" />Fernzugriff<Badge variant="outline" className={cls}>{state}</Badge></CardTitle>
        <CardDescription>
          Das LAN dieses Standorts im Techniker-Stack. Die Box ist dort Peer, sobald sie zugeordnet ist und ihren Operator-Daemon meldet; hier wird ihr LAN als Netzwerk freigeschaltet. Kein Tunnelwechsel mehr, kein Profil.
          {d.boxOperator && <> · Box im Techniker-Stack: {d.boxOperator === "connected" ? <>verbunden <span className="font-mono">{d.boxOpIp}</span></> : d.boxOperator}</>}
        </CardDescription>
        {a && (
          <CardAction className="flex gap-2">
            {a.Enabled && a.State !== "error"
              ? <Button size="sm" variant="outline" onClick={() => m.mutate({ path: `/api/sites/${siteId}/remote/disable` })} disabled={m.isPending || !!busy}><PowerOff />Abschalten</Button>
              : null}
            <AlertDialog>
              <AlertDialogTrigger asChild><Button size="sm" variant="ghost" className="text-destructive"><Trash2 />Entfernen</Button></AlertDialogTrigger>
              <AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Fernzugriff entfernen?</AlertDialogTitle><AlertDialogDescription>Netzwerk, Ressource und Router werden im Techniker-Stack gelöscht. Die Box bleibt dort Peer und kann jederzeit wieder eingeschaltet werden.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Abbrechen</AlertDialogCancel><AlertDialogAction onClick={() => m.mutate({ path: `/api/sites/${siteId}/remote/remove` })}>Entfernen</AlertDialogAction></AlertDialogFooter></AlertDialogContent>
            </AlertDialog>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {!d.configured && <p className="text-sm text-muted-foreground">Der Techniker-Stack ist noch nicht eingetragen: <Link className="underline" to="/settings">Verwaltung → Einstellungen</Link>.</p>}
        {a && (
          <div className="grid gap-1 text-sm">
            <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Netz</span><span className="font-mono">{a.CIDR}</span></div>
            <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Stand</span><span className={a.State === "error" ? "text-destructive" : ""}>{a.Detail || "–"} <span className="text-muted-foreground">· <Ago t={a.UpdatedAt} /></span></span></div>
            {a.PeerIP && <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Peer der Box</span><span className="font-mono">{a.PeerIP}</span></div>}
          </div>
        )}
        {(!a || !a.Enabled || a.State === "error") && (
          <div className="flex flex-wrap items-end gap-2">
            <div className="grid gap-1"><Label htmlFor="ra-cidr">LAN (CIDR)</Label><Input id="ra-cidr" value={value} onChange={(e) => setCidr(e.target.value)} placeholder="192.168.10.0/24" className="w-56 font-mono" /></div>
            <Button size="sm" onClick={() => m.mutate({ path: `/api/sites/${siteId}/remote/enable`, form: { cidr: value } })} disabled={m.isPending || !d.configured || !value}><Power />{a ? "Wieder einschalten" : "Einschalten"}</Button>
            {d.suggested && !a && <span className="text-xs text-muted-foreground">Vorschlag aus den Geräten: {d.suggested}</span>}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
