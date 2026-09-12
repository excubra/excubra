import { Link } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Siren } from "lucide-react"
import { toast } from "sonner"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Skeleton } from "@/components/ui/skeleton"
import { get, post, type SiteScan } from "@/lib/api"

const decoyNames: Record<number, string> = { 21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 5985: "WinRM", 8080: "HTTP" }

// The live detection (ADR-0018 §7): decoy ports on the box and the signals behind
// them. On by default; the switch is for the rare site that objects.
export function CanaryCard({ siteId }: { siteId: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["site-scan", siteId], queryFn: () => get<SiteScan>(`/api/sites/${siteId}/scan`), refetchInterval: 30_000 })
  const m = useMutation({
    mutationFn: (enabled: boolean) => post(`/api/sites/${siteId}/canary`, { enabled: enabled ? "1" : "0" }),
    onSuccess: (r) => { toast.success(r.message); qc.invalidateQueries({ queryKey: ["site-scan", siteId] }) },
    onError: (e) => toast.error(e.message),
  })
  const d = q.data
  if (!d) return <Skeleton className="h-36" />
  const armed = d.armed ?? []
  return (
    <Card className={d.signals > 0 ? "border-destructive/40" : ""}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Siren className="size-4" />Live-Erkennung<Badge variant="outline" className={d.canary ? "border-primary/40 text-primary" : "text-muted-foreground"}>{d.canary ? "an" : "aus"}</Badge></CardTitle>
        <CardDescription>Die Box gibt sich als das aus, was ein Eindringling sucht: Freigaben, Fernwartung, Datenbank. Kein echtes Gerät klopft dort an. Wer es tut, wer die Box abtastet, wer das Netz absucht oder das Gateway nachahmt, wird in der Minute gemeldet: als Ereignis und als Finding am Gerät, aus dem es kommt. Die Box antwortet nichts und sendet nichts.</CardDescription>
        <CardAction>
          <label className="flex items-center gap-2 text-sm"><span className="text-muted-foreground">{d.hasBox ? "Köder" : "keine Box"}</span><Switch checked={d.canary} disabled={!d.hasBox || m.isPending} onCheckedChange={(on) => m.mutate(on)} /></label>
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-1 text-sm">
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Köder-Ports</span><span>{armed.length > 0 ? armed.map((p) => <span key={p} className="mr-2 font-mono">{p}{decoyNames[p] ? <span className="text-muted-foreground"> {decoyNames[p]}</span> : null}</span>) : d.canary ? <span className="text-muted-foreground">{d.hasBox ? "noch keine gemeldet; die Box öffnet sie mit dem nächsten Heartbeat (Agent ab 0.5)" : "–"}</span> : <span className="text-muted-foreground">geschlossen</span>}</span></div>
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Sieht immer</span><span className="text-muted-foreground">Anklopfen an jedem Port der Box, auch geblockte; ARP-Absuchen des Netzes; eine Adresse, die die MAC wechselt</span></div>
        <div className="grid grid-cols-[140px_1fr] gap-3"><span className="text-muted-foreground">Findings</span><span>{d.signals > 0 ? <Link className="underline text-destructive" to="/findings">{d.signals} offen aus der Live-Erkennung</Link> : "keine offenen; ein Signal, das einen Tag still war, schließt sich von selbst"}</span></div>
      </CardContent>
    </Card>
  )
}
