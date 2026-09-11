import { useState } from "react"
import { Link } from "react-router"
import { useMutation } from "@tanstack/react-query"
import { Check, ShieldAlert, Undo2 } from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Ago } from "@/components/clock"
import { post, type FindingView } from "@/lib/api"
import { fmtDateTime } from "@/lib/format"

export const SEVERITY: Record<FindingView["severity"], { label: string; cls: string }> = {
  high: { label: "hoch", cls: "border-destructive/50 text-destructive" },
  medium: { label: "mittel", cls: "border-foreground/40 text-foreground" },
  low: { label: "niedrig", cls: "text-muted-foreground" },
}

export function SeverityBadge({ s }: { s: FindingView["severity"] }) {
  return <Badge variant="outline" className={"shrink-0 " + SEVERITY[s].cls}>{SEVERITY[s].label}</Badge>
}

// Findings, worst first. Each can be acknowledged with a note, like every other problem.
export function FindingsList({ items, onChanged, showDevice = true, emptyText = "Die Regeln haben nichts zu beanstanden." }: { items: FindingView[]; onChanged: () => void; showDevice?: boolean; emptyText?: string }) {
  const [ack, setAck] = useState<FindingView | null>(null)
  const [note, setNote] = useState("")
  const m = useMutation({
    mutationFn: ({ path, form }: { path: string; form: Record<string, string> }) => post(path, form),
    onSuccess: (r) => { toast.success(r.message); setAck(null); setNote(""); onChanged() },
    onError: (e) => toast.error(e.message),
  })
  if (items.length === 0) return <Empty className="border"><EmptyHeader><EmptyMedia variant="icon"><ShieldAlert /></EmptyMedia><EmptyTitle>Nichts offen</EmptyTitle><EmptyDescription>{emptyText}</EmptyDescription></EmptyHeader></Empty>
  return (
    <>
      <ul className="flex flex-col gap-2">
        {items.map((f) => (
          <li key={f.id} className={"rounded-md border px-3 py-2 " + (f.resolvedAt ? "opacity-60" : f.ack ? "opacity-70" : f.severity === "high" ? "border-destructive/40" : "")}>
            <div className="flex flex-wrap items-start gap-2">
              <SeverityBadge s={f.severity} />
              <div className="min-w-0 flex-1">
                <div className="font-medium">{f.title}</div>
                <div className="text-xs text-muted-foreground">
                  {showDevice && <><Link to={`/devices/${f.deviceId}?tab=praevention`} className="hover:underline">{f.device || f.deviceId}</Link> · {f.tenant}{f.site ? ` · ${f.site}` : ""} · </>}
                  {f.resolvedAt ? <>behoben {fmtDateTime(f.resolvedAt)}, bestand seit {fmtDateTime(f.firstSeen)}</> : <>seit <Ago t={f.firstSeen} /> · zuletzt bestätigt <Ago t={f.lastSeen} /></>}
                  {f.ack && <> · quittiert von {f.ack.actor} <Ago t={f.ack.at} />{f.ack.note ? ` · „${f.ack.note}“` : ""}</>}
                </div>
                <p className="mt-1 text-sm text-muted-foreground">{f.detail}</p>
              </div>
              {!f.resolvedAt && (f.ack
                ? <Button variant="ghost" size="icon" className="size-8" title="Quittierung zurücknehmen" onClick={() => m.mutate({ path: "/api/ack/delete", form: { kind: "finding", id: f.id } })}><Undo2 /></Button>
                : <Button variant="outline" size="sm" onClick={() => setAck(f)}><Check />Quittieren</Button>)}
            </div>
          </li>
        ))}
      </ul>
      <Dialog open={ack !== null} onOpenChange={(o) => { if (!o) setAck(null) }}>
        <DialogContent>
          <DialogHeader><DialogTitle>Finding quittieren</DialogTitle><DialogDescription>{ack?.title}. Bleibt sichtbar, zählt aber nicht mehr als offen. Verschwindet die Ursache, verfällt die Quittierung von selbst.</DialogDescription></DialogHeader>
          <div className="grid gap-2"><Label htmlFor="fnd-note">Notiz (optional)</Label><Input id="fnd-note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="z. B. bewusst so, Kunde will Fernwartung über WAN" maxLength={200} /></div>
          <DialogFooter><Button variant="outline" onClick={() => setAck(null)}>Abbrechen</Button><Button onClick={() => ack && m.mutate({ path: "/api/ack", form: { kind: "finding", id: ack.id, since: ack.firstSeen, note } })} disabled={m.isPending}>Quittieren</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
