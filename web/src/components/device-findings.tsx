import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Bot } from "lucide-react"
import { FindingsList } from "@/components/findings-list"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type FindingsData } from "@/lib/api"

// The prevention tab of a device: open findings, recently resolved ones, and the
// place where the AI triage will explain them later.
export function DeviceFindings({ deviceId }: { deviceId: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["device-findings", deviceId], queryFn: () => get<FindingsData>(`/api/devices/${deviceId}/findings`), refetchInterval: 60_000 })
  const d = q.data
  const refresh = () => { qc.invalidateQueries({ queryKey: ["device-findings", deviceId] }); qc.invalidateQueries({ queryKey: ["findings"] }); qc.invalidateQueries({ queryKey: ["me"] }) }
  if (!d) return <Skeleton className="h-48" />
  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader><CardTitle>Findings</CardTitle><CardDescription>Regeln über die letzte Lesung des Konnektors, bei jeder Lesung neu geprüft. Offen, bis die Ursache weg ist.</CardDescription></CardHeader>
        <CardContent><FindingsList items={d.open} onChanged={refresh} showDevice={false} emptyText="Die Regeln haben an diesem Gerät nichts zu beanstanden." /></CardContent>
      </Card>
      {(d.resolved?.length ?? 0) > 0 && (
        <Card>
          <CardHeader><CardTitle>Behoben in den letzten 30 Tagen</CardTitle></CardHeader>
          <CardContent><FindingsList items={d.resolved ?? []} onChanged={refresh} showDevice={false} /></CardContent>
        </Card>
      )}
      <Card className="border-dashed">
        <CardHeader><CardTitle className="flex items-center gap-2"><Bot className="size-4" />KI-Triage</CardTitle><CardDescription>Kommt als Stufe V6: liest Finding plus Kontext, erklärt in zwei Sätzen, was los ist, und legt die Behebung als Auftragsentwurf an. Ausführen darf nur, was ein Mensch signiert.</CardDescription></CardHeader>
      </Card>
    </div>
  )
}
