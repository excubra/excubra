import { Link } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Sparkles } from "lucide-react"
import { toast } from "sonner"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Ago } from "@/components/clock"
import { get, post, type SiteAI } from "@/lib/api"

// The AI's assessment of a site (ADR-0019): it reads the situation and says what
// matters; nothing here executes anything.
export function AICard({ siteId, tenantId }: { siteId: string; tenantId: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["site-ai", siteId], queryFn: () => get<SiteAI>(`/api/sites/${siteId}/ai`), refetchInterval: (query) => (query.state.data?.busy ? 5_000 : 60_000) })
  const m = useMutation({
    mutationFn: () => post(`/api/sites/${siteId}/ai/assess`),
    onSuccess: (r) => { toast.success(r.message); qc.invalidateQueries({ queryKey: ["site-ai", siteId] }) },
    onError: (e) => toast.error(e.message),
  })
  const d = q.data
  if (!d) return <Skeleton className="h-48" />
  const b = d.latest
  const riskCls = (r: string) => r === "hoch" ? "border-destructive/40 text-destructive" : r === "niedrig" ? "border-primary/40 text-primary" : "border-foreground/40"
  const sevCls = (s: string) => s === "high" ? "text-destructive" : s === "low" ? "text-muted-foreground" : ""
  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Sparkles className="size-4" />KI-Einschätzung{b && <Badge variant="outline" className={riskCls(b.Risk)}>Risiko {b.Risk}</Badge>}</CardTitle>
          <CardDescription>
            Das Modell liest das Lagebild dieses Standorts, Geräte, Dienste, Findings, Ereignisse, Konnektor-Facts, und sagt, was zählt. Es führt nichts aus. Jeder Aufruf steht im Audit.
            {d.scope !== "facts" && <> · <span className="text-foreground">Für diesen Kunden ist die KI aus</span>, einschalten unter <Link className="underline" to={`/tenants/${tenantId}`}>Kunde</Link>.</>}
            {!d.available && <> · Kein Anbieter eingetragen: <Link className="underline" to="/settings">Einstellungen</Link>.</>}
          </CardDescription>
          <CardAction>
            <Button size="sm" onClick={() => m.mutate()} disabled={m.isPending || d.busy || !d.available || d.scope !== "facts"}>{d.busy ? "läuft …" : "Jetzt einschätzen"}</Button>
          </CardAction>
        </CardHeader>
        {b ? (
          <CardContent className="flex flex-col gap-4">
            <p className="max-w-[80ch] text-sm">{b.Summary}</p>
            {b.Result.priorities?.length ? (
              <ol className="flex flex-col gap-2">
                {b.Result.priorities.map((p, i) => (
                  <li key={i} className="grid grid-cols-[24px_1fr] gap-2 text-sm">
                    <span className="font-mono text-xs text-muted-foreground">{i + 1}.</span>
                    <div><div className={"font-medium " + sevCls(p.severity)}>{p.title}{p.device_id && <> · <Link className="font-normal underline" to={`/devices/${p.device_id}`}>Gerät</Link></>}</div><div className="text-muted-foreground">{p.why}</div><div>{p.action}</div></div>
                  </li>
                ))}
              </ol>
            ) : <p className="text-sm text-muted-foreground">Keine Prioritäten, nichts Dringendes.</p>}
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span><Ago t={b.At} /> · {b.Provider} {b.Model} · {Math.round(b.PromptBytes / 1024)} KB gesendet · {Math.round(b.DurationMS / 1000)} s · angefragt von {b.RequestedBy}</span>
              {d.findings > 0 && <Link className="underline" to="/findings">{d.findings} Findings vom Modell offen</Link>}
            </div>
          </CardContent>
        ) : (
          <CardContent><p className="text-sm text-muted-foreground">{d.scope === "facts" && d.available ? "Noch keine Einschätzung. Nachts um fünf kommt die erste, oder oben rechts jetzt anfordern." : "Noch keine Einschätzung."}</p></CardContent>
        )}
      </Card>
      {d.history.length > 1 && (
        <Card>
          <CardHeader><CardTitle>Verlauf</CardTitle><CardDescription>Die letzten Einschätzungen, neueste zuerst.</CardDescription></CardHeader>
          <CardContent className="flex flex-col gap-2 text-sm">
            {d.history.slice(1).map((h) => <div key={h.ID} className="grid grid-cols-[110px_80px_1fr] gap-3"><span className="text-muted-foreground"><Ago t={h.At} /></span><Badge variant="outline" className={riskCls(h.Risk) + " w-fit"}>{h.Risk}</Badge><span>{h.Summary}</span></div>)}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
