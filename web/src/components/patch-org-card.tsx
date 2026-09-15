import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link } from "react-router"
import { ShieldCheck } from "lucide-react"
import { toast } from "sonner"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { get, post, type PatchesData } from "@/lib/api"

const NONE = "__none"

// Which customer is which organization in the endpoint manager. Picked from the
// list the credential really sees, never typed: one wrong row would put one
// customer's machines on another customer's page.
export function PatchOrgCard({ tenantId, tenantName }: { tenantId: string; tenantName: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["patches"], queryFn: () => get<PatchesData>("/api/patches") })
  const d = q.data
  const current = (d?.links ?? []).find((l) => l.tenantId === tenantId)
  const [pick, setPick] = useState<string>()
  const chosen = pick ?? current?.orgId ?? NONE
  const m = useMutation({
    mutationFn: (org: string) => post("/api/patches/link", { tenant: tenantId, org }),
    onSuccess: (r) => { toast.success(r.message); qc.invalidateQueries({ queryKey: ["patches"] }); qc.invalidateQueries({ queryKey: ["tenant", tenantId] }) },
    onError: (e) => toast.error(e.message),
  })

  if (q.isLoading) return <Skeleton className="h-32" />
  if (!d?.configured) return null

  const taken = new Set((d.links ?? []).filter((l) => l.tenantId !== tenantId).map((l) => l.orgId))
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><ShieldCheck className="size-4" />Patch-Stand der Windows-Maschinen</CardTitle>
        <CardDescription>
          Der Scan liest Banner aus dem Netz, und eine Windows-Anwendung hat keines. Der Endpunkt-Manager hat einen Agenten auf der Maschine und weiß es genau.
          Verknüpft man diesen Kunden mit seiner Organisation dort, erscheinen fehlende Updates und bekannte Lücken je Gerät unter <Link className="underline" to="/findings">Prävention</Link>.
          Es wird nur gelesen; verteilt wird nichts.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {d.orgErr && <p className="text-sm text-destructive">Die Organisationen lassen sich gerade nicht lesen: {d.orgErr}</p>}
        <div className="flex flex-wrap items-center gap-2">
          <Select value={chosen} onValueChange={setPick}>
            <SelectTrigger className="w-full sm:w-80"><SelectValue placeholder="Organisation wählen" /></SelectTrigger>
            <SelectContent>
              <SelectItem value={NONE}>— nicht verknüpft —</SelectItem>
              {(d.orgs ?? []).map((o) => (
                <SelectItem key={o.id} value={o.id} disabled={taken.has(o.id)}>
                  {o.name}{taken.has(o.id) ? " · schon vergeben" : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button size="sm" disabled={m.isPending || chosen === (current?.orgId ?? NONE)}
            onClick={() => m.mutate(chosen === NONE ? "" : chosen)}>
            {chosen === NONE && current ? "Verknüpfung lösen" : "Verknüpfen"}
          </Button>
        </div>
        {current ? (
          <p className="text-sm text-muted-foreground">{tenantName} liest aus „{current.orgName}". Der Abgleich läuft stündlich.</p>
        ) : (
          <p className="text-sm text-muted-foreground">Noch nicht verknüpft. Ohne Verknüpfung wird für diesen Kunden nichts gelesen.</p>
        )}
        {d.status?.unmatched?.length ? (
          <p className="text-sm text-muted-foreground">
            {d.status.unmatched.length} Maschine{d.status.unmatched.length === 1 ? "" : "n"} ohne Gerät — unten in der Liste, dort lässt sich das Gerät auswählen.
          </p>
        ) : null}
      </CardContent>
    </Card>
  )
}
