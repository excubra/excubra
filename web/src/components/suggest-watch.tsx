import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Sparkles } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog"
import { get, post, type WatchSuggestion } from "@/lib/api"

// One button instead of fifty switches. The rule lives on the server; this only
// asks what it would do, shows the answer, and lets an operator say yes — because
// a proposal that acts before you have read it is not a proposal.
export function SuggestWatchButton({ siteId, onDone }: { siteId: string; onDone: () => void }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const q = useQuery({
    queryKey: ["watch-suggestion", siteId],
    queryFn: () => get<WatchSuggestion>(`/api/sites/${siteId}/watch/suggestion`),
    enabled: open,
  })
  const apply = useMutation({
    mutationFn: () => post(`/api/sites/${siteId}/watch/suggested`),
    onSuccess: (r) => {
      toast.success(r.message)
      setOpen(false)
      qc.invalidateQueries({ queryKey: ["watch-suggestion", siteId] })
      onDone()
    },
    onError: (e) => toast.error(e.message),
  })

  const d = q.data
  const skipped = Object.entries(d?.skipped ?? {}).sort((a, b) => b[1] - a[1])

  return (
    <>
      <Button size="sm" variant="outline" onClick={() => setOpen(true)}><Sparkles />Beobachten, was zählt</Button>
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Beobachten, was zählt</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="flex flex-col gap-3 text-sm">
                <p>
                  Aufgenommen wird, was an Ort und Stelle bleibt, seine Adresse behält und fehlt, wenn es weg ist:
                  Firewall, Netzwerk, Server, VM, Telefonie, Drucker. Notebooks und Handys bleiben draußen, sonst
                  meldet die Box jeden Feierabend einen Ausfall.
                </p>
                {q.isLoading && <p className="text-muted-foreground">Sieht nach …</p>}
                {d && !d.hasBox && <p className="text-destructive">Diesem Standort ist keine Box zugeordnet; ohne Box kann nichts geprüft werden.</p>}
                {d && d.count === 0 && d.hasBox && <p>Nichts hinzuzufügen.</p>}
                {d && d.count > 0 && (
                  <div>
                    <p className="font-medium text-foreground">{d.count} Gerät{d.count === 1 ? "" : "e"} kommen dazu:</p>
                    <ul className="mt-1 max-h-40 overflow-y-auto text-muted-foreground">
                      {(d.names ?? []).map((n) => <li key={n}>{n}</li>)}
                    </ul>
                  </div>
                )}
                {skipped.length > 0 && (
                  <div>
                    <p className="font-medium text-foreground">Übergangen:</p>
                    <ul className="mt-1 text-muted-foreground">
                      {skipped.map(([reason, n]) => <li key={reason}>{n}× {reason}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction disabled={!d || d.count === 0 || !d.hasBox || apply.isPending} onClick={(e) => { e.preventDefault(); apply.mutate() }}>
              {apply.isPending ? "Nimmt auf …" : `${d?.count ?? 0} aufnehmen`}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
