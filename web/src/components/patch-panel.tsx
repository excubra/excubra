import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, PackageSearch, ShieldCheck, Unlink } from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Ago } from "@/components/clock"
import { get, post, type DevicePatch, type MachineApp, type MachineCVE, type PatchMachine } from "@/lib/api"

function sev(c: MachineCVE): "destructive" | "secondary" | "outline" {
  if (c.kev || c.cvss >= 9) return "destructive"
  if (c.cvss >= 7) return "secondary"
  return "outline"
}

/** What the endpoint manager knows about this device — so nobody opens a second portal. */
export function PatchPanel({ deviceId }: { deviceId: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["device-patch", deviceId], queryFn: () => get<DevicePatch>(`/api/devices/${deviceId}/patch`) })
  // Both values are carried on purpose: assigning and letting go differ in the
  // device, never in the machine, and an empty machine id addresses nothing.
  const assign = useMutation({
    mutationFn: ({ endpoint, device }: { endpoint: string; device: string }) => post("/api/patches/assign", { endpoint, device }),
    onSuccess: (r) => {
      toast.success(r.message)
      qc.invalidateQueries({ queryKey: ["device-patch", deviceId] })
      qc.invalidateQueries({ queryKey: ["patch-machines"] })
      qc.invalidateQueries({ queryKey: ["device", deviceId] })
    },
    onError: (e) => toast.error(e.message),
  })
  const [pick, setPick] = useState("")
  const [filter, setFilter] = useState("")

  if (q.isLoading) return <Skeleton className="h-64" />
  const d = q.data
  if (!d) return null

  if (!d.linked) {
    const free = d.free ?? []
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><PackageSearch className="size-4" />Keine Maschine zugeordnet</CardTitle>
          <CardDescription>
            Der Endpunkt-Manager sieht in eine Windows-Maschine hinein, ein Scan von außen nicht. Zugeordnet wird über den Hostnamen — wenn der drüben anders heißt, wählt man hier von Hand. Die Zuweisung bleibt danach stehen, auch wenn die Namen nie zusammenpassen.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {free.length === 0 ? (
            <p className="text-sm text-muted-foreground">Für diesen Kunden ist keine Maschine mehr frei. Entweder gehört jede schon zu einem Gerät, oder der Kunde ist nicht mit einer Organisation verknüpft — das steht auf der Kundenseite.</p>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <Select value={pick} onValueChange={setPick}>
                <SelectTrigger className="w-full sm:w-96"><SelectValue placeholder="Maschine wählen" /></SelectTrigger>
                <SelectContent>
                  {free.map((m) => (
                    <SelectItem key={m.endpointId} value={m.endpointId}>
                      {m.name}{m.online ? "" : " · offline"}{m.cveCount > 0 ? ` · ${m.cveCount} Lücken` : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button size="sm" disabled={!pick || assign.isPending} onClick={() => assign.mutate({ endpoint: pick, device: deviceId })}>Diesem Gerät zuordnen</Button>
            </div>
          )}
        </CardContent>
      </Card>
    )
  }

  const m = d.machine as PatchMachine
  const cves = m.cves ?? []
  const apps = m.software ?? []
  const shown = filter.trim()
    ? apps.filter((a) => (a.name + " " + a.version + " " + (a.vendor ?? "")).toLowerCase().includes(filter.trim().toLowerCase()))
    : apps
  const stale = m.inventoried && m.lastSeen && new Date(m.inventoried) < new Date(new Date(m.lastSeen).getTime() - 7 * 864e5)

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            <ShieldCheck className="size-4" />{m.name}
            <Badge variant={m.online ? "outline" : "secondary"}>{m.online ? "Agent verbunden" : "Agent offline"}</Badge>
            {m.pinned && <Badge variant="secondary">von Hand zugeordnet</Badge>}
          </CardTitle>
          <CardDescription>
            Letzter Kontakt mit dem Manager <Ago t={m.lastSeen} />, Inventur <Ago t={m.inventoried} />, Abgleich <Ago t={m.syncedAt} />.
            {stale ? " Die Inventur ist deutlich älter als der letzte Kontakt — was hier steht, kann überholt sein." : ""}
            {" "}EX0 liest nur; verteilt wird im Manager.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-2">
          <Badge variant={m.cveCount > 0 ? (m.kev || m.worstCvss >= 7 ? "destructive" : "secondary") : "outline"}>
            {m.cveCount} bekannte Lücke{m.cveCount === 1 ? "" : "n"}
          </Badge>
          <Badge variant={m.pending > 0 ? "secondary" : "outline"}>{m.pending} offene Update{m.pending === 1 ? "" : "s"}</Badge>
          <Badge variant="outline">{apps.length} Anwendungen</Badge>
          <Button size="sm" variant="ghost" className="ml-auto" disabled={assign.isPending} onClick={() => assign.mutate({ endpoint: m.endpointId, device: "" })}>
            <Unlink className="size-3.5" />Zuordnung lösen
          </Button>
        </CardContent>
      </Card>

      {cves.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><AlertTriangle className="size-4" />Bekannte Lücken auf dieser Maschine</CardTitle>
            <CardDescription>Aus der Schwachstellenliste des Managers, zugeordnet über Produkt und Version aus dem Software-Bestand dieser Maschine — exakt, nicht geschätzt.</CardDescription>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <Table>
              <TableHeader><TableRow>
                <TableHead>CVE</TableHead><TableHead>Anwendung</TableHead><TableHead>CVSS</TableHead>
                <TableHead>Frist</TableHead><TableHead>Paket da?</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {[...cves].sort((a, b) => b.cvss - a.cvss).map((c) => (
                  <TableRow key={c.cve}>
                    <TableCell className="font-mono whitespace-nowrap">
                      {c.cve}{c.kev && <Badge variant="destructive" className="ml-2">wird ausgenutzt</Badge>}
                    </TableCell>
                    <TableCell>{c.product} <span className="text-muted-foreground font-mono">{c.version}</span></TableCell>
                    <TableCell><Badge variant={sev(c)}>{c.cvss.toFixed(1)}</Badge></TableCell>
                    <TableCell className="whitespace-nowrap">
                      {c.deadline && !c.deadline.startsWith("0001") ? <Ago t={c.deadline} /> : "—"}
                      {c.status?.toLowerCase() === "overdue" && <Badge variant="destructive" className="ml-2">überfällig</Badge>}
                    </TableCell>
                    <TableCell>{c.patchable ? "ja" : <span className="text-muted-foreground">nein — Hersteller-Update nötig</span>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Installierte Software</CardTitle>
          <CardDescription>Was der Agent auf der Maschine gefunden hat. Das ist die Antwort, die kein Scan von außen geben kann.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Anwendung suchen" className="w-full sm:w-80" />
          <div className="max-h-[28rem] overflow-auto rounded-md border">
            <Table>
              <TableHeader><TableRow><TableHead>Anwendung</TableHead><TableHead>Version</TableHead><TableHead>Hersteller</TableHead><TableHead>Update bereit</TableHead></TableRow></TableHeader>
              <TableBody>
                {shown.length === 0 ? (
                  <TableRow><TableCell colSpan={4} className="text-muted-foreground">Nichts gefunden.</TableCell></TableRow>
                ) : shown.map((a: MachineApp, i) => (
                  <TableRow key={a.name + a.version + i}>
                    <TableCell>{a.name}</TableCell>
                    <TableCell className="font-mono">{a.version || "—"}</TableCell>
                    <TableCell className="text-muted-foreground">{a.vendor || "—"}</TableCell>
                    <TableCell>{a.update ? <Badge variant="secondary" className="font-mono">{a.update}</Badge> : "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
