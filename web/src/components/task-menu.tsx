import { useState } from "react"
import { useMutation } from "@tanstack/react-query"
import { ChevronDown, Download, ListChecks, Radar, RotateCw, Zap } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog"
import { post } from "@/lib/api"

// The closed list of things a box can be asked to do (ADR-0014). Order is display order.
export const TASKS: { kind: string; label: string; desc: string; icon: typeof Radar; confirm?: string }[] = [
  { kind: "sweep", label: "Netz absuchen", desc: "Ein Discovery-Durchlauf jetzt statt beim nächsten Intervall", icon: Radar },
  { kind: "recheck", label: "Hosts jetzt prüfen", desc: "Eine Prüfrunde über alle beobachteten Hosts", icon: ListChecks },
  { kind: "update", label: "Update holen", desc: "Die Box fragt sofort nach dem Release ihres Kanals", icon: Download },
  { kind: "restart", label: "Agent neu starten", desc: "Der Agent beendet sich, der Dienst startet ihn neu", icon: RotateCw, confirm: "Der Agent beendet sich nach dem nächsten Heartbeat und wird vom Dienst neu gestartet. Prüfungen setzen für einige Sekunden aus; Ereignisse gehen nicht verloren." },
]

export function taskLabel(kind: string) { return TASKS.find((t) => t.kind === kind)?.label ?? kind }

// A dropdown that queues one task for a box; `path` is the tasks endpoint of a box or a site.
export function TaskMenu({ path, onDone, label = "Aktionen", variant = "outline" }: { path: string; onDone?: () => void; label?: string; variant?: "outline" | "default" }) {
  const [confirm, setConfirm] = useState<typeof TASKS[number] | null>(null)
  const m = useMutation({
    mutationFn: (kind: string) => post(path, { kind }),
    onSuccess: (r) => { toast.success(r.message); onDone?.() },
    onError: (e) => toast.error(e.message),
  })
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild><Button variant={variant} size="sm" disabled={m.isPending}><Zap />{label}<ChevronDown className="opacity-60" /></Button></DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-80">
          <DropdownMenuLabel>Aufgabe an die Box</DropdownMenuLabel>
          <DropdownMenuSeparator />
          {TASKS.map((t) => (
            <DropdownMenuItem key={t.kind} onSelect={() => (t.confirm ? setConfirm(t) : m.mutate(t.kind))}>
              <t.icon />
              <div className="flex min-w-0 flex-col"><span>{t.label}</span><span className="text-xs text-muted-foreground">{t.desc}</span></div>
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <p className="px-2 py-1.5 text-xs text-muted-foreground">Die Box holt Aufgaben mit dem nächsten Heartbeat (bis zu 1 min) und meldet das Ergebnis mit dem übernächsten.</p>
        </DropdownMenuContent>
      </DropdownMenu>
      <AlertDialog open={confirm !== null} onOpenChange={(o) => { if (!o) setConfirm(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader><AlertDialogTitle>{confirm?.label}?</AlertDialogTitle><AlertDialogDescription>{confirm?.confirm}</AlertDialogDescription></AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction onClick={() => { if (confirm) m.mutate(confirm.kind); setConfirm(null) }}>{confirm?.label}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
