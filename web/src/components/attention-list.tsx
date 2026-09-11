import { useState } from "react"
import { useNavigate } from "react-router"
import { useMutation } from "@tanstack/react-query"
import { AlertTriangle, Check, Undo2 } from "lucide-react"
import { toast } from "sonner"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { LiveDot } from "@/components/status"
import { Ago } from "@/components/clock"
import { post, type Attention } from "@/lib/api"
import { fmtDateTime } from "@/lib/format"

const KIND_LABEL: Record<string, string> = { host_down: "ausgefallen", box_silent: "Box schweigt", box_unassigned: "Box ohne Standort" }

// The problems that need a person, with a way to say "seen". Acknowledged ones stay
// listed but muted; the server drops the acknowledgement when the problem ends.
export function AttentionCard({ items, onChanged }: { items: Attention[]; onChanged: () => void }) {
  const navigate = useNavigate()
  const [ack, setAck] = useState<Attention | null>(null)
  const [note, setNote] = useState("")
  const m = useMutation({
    mutationFn: ({ path, form }: { path: string; form: Record<string, string> }) => post(path, form),
    onSuccess: (r) => { toast.success(r.message); setAck(null); setNote(""); onChanged() },
    onError: (e) => toast.error(e.message),
  })
  if (items.length === 0) return null
  const open = items.filter((a) => !a.ack).length
  const seen = items.length - open
  return (
    <Card className={open ? "border-destructive/40" : ""}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><AlertTriangle className={"size-4 " + (open ? "text-destructive" : "text-muted-foreground")} />Störungen</CardTitle>
        <CardDescription>{open ? `${open} offen, älteste zuerst.` : "Alles Offene ist quittiert."}{seen ? ` ${seen} quittiert: bleibt sichtbar, bis es behoben ist.` : ""} Ein Klick führt zum Betroffenen.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-2 @3xl/main:grid-cols-2 @6xl/main:grid-cols-3">
        {items.map((a) => (
          <div key={a.kind + a.id} className={"flex items-center gap-3 rounded-md border px-3 py-2 " + (a.ack ? "opacity-60" : "")}>
            {a.ack ? <span className="size-2 shrink-0 rounded-full bg-muted-foreground" /> : <LiveDot ok={false} />}
            <button onClick={() => navigate(a.href)} className="min-w-0 flex-1 text-left">
              <div className="truncate font-medium">{a.name}{a.address && <span className="ml-2 font-mono text-xs text-muted-foreground">{a.address}</span>}</div>
              <div className="truncate text-xs text-muted-foreground">{KIND_LABEL[a.kind] ?? a.kind} · {a.tenant ? `${a.tenant} · ${a.site}` : a.detail} · seit <Ago t={a.since} /></div>
              {a.ack && <div className="truncate text-xs text-muted-foreground">quittiert von {a.ack.actor} <Ago t={a.ack.at} />{a.ack.note ? ` · „${a.ack.note}“` : ""}</div>}
            </button>
            {a.ack
              ? <Button variant="ghost" size="icon" className="size-8" title="Quittierung zurücknehmen" onClick={() => m.mutate({ path: "/api/ack/delete", form: { kind: a.kind, id: a.id } })}><Undo2 /></Button>
              : <Button variant="outline" size="sm" onClick={() => setAck(a)}><Check />Quittieren</Button>}
          </div>
        ))}
      </CardContent>
      <Dialog open={ack !== null} onOpenChange={(o) => { if (!o) setAck(null) }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Störung quittieren</DialogTitle>
            <DialogDescription>{ack?.name}: {KIND_LABEL[ack?.kind ?? ""] ?? ""} seit {ack ? fmtDateTime(ack.since) : ""}. Sie bleibt sichtbar, zählt aber nicht mehr als offen. Behebt sie sich, verfällt die Quittierung von selbst.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-2"><Label htmlFor="ack-note">Notiz (optional)</Label><Input id="ack-note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="z. B. Ticket 4711, Techniker unterwegs" maxLength={200} /></div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAck(null)}>Abbrechen</Button>
            <Button onClick={() => ack && m.mutate({ path: "/api/ack", form: { kind: ack.kind, id: ack.id, since: ack.since, note } })} disabled={m.isPending}>Quittieren</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
