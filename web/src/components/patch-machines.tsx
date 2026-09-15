import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link } from "react-router"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Ago } from "@/components/clock"
import { get, post, type PatchMachine, type PatchMachinesData } from "@/lib/api"

const NONE = "__none"

/** Every machine the manager knows for this customer, and which device it is here. */
export function PatchMachines({ tenantId }: { tenantId: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["patch-machines", tenantId], queryFn: () => get<PatchMachinesData>("/api/patches/machines", { tenant: tenantId }) })
  const [open, setOpen] = useState<string>()
  const m = useMutation({
    mutationFn: ({ endpoint, device }: { endpoint: string; device: string }) => post("/api/patches/assign", { endpoint, device }),
    onSuccess: (r) => {
      toast.success(r.message)
      setOpen(undefined)
      qc.invalidateQueries({ queryKey: ["patch-machines", tenantId] })
      qc.invalidateQueries({ queryKey: ["patches"] })
    },
    onError: (e) => toast.error(e.message),
  })

  if (q.isLoading) return <Skeleton className="h-40" />
  const machines = q.data?.machines ?? []
  const devices = q.data?.devices ?? []
  if (machines.length === 0) return null
  const orphans = machines.filter((x) => !x.deviceId).length

  return (
    <Card>
      <CardHeader>
        <CardTitle>Maschinen im Endpunkt-Manager</CardTitle>
        <CardDescription>
          {machines.length} Maschine{machines.length === 1 ? "" : "n"}, {machines.length - orphans} einem Gerät zugeordnet.
          {orphans > 0 ? " Die ohne Gerät stehen oben: Ihr Name drüben passt zu keinem Gerät, das eine Box gesehen hat — such das richtige aus, dann bleibt die Zuweisung." : " Alles zugeordnet."}
          {" "}Der Patch-Stand steht dann beim Gerät, nicht in einem zweiten Portal.
        </CardDescription>
      </CardHeader>
      <CardContent className="overflow-x-auto">
        <Table>
          <TableHeader><TableRow>
            <TableHead>Maschine</TableHead><TableHead>Agent</TableHead><TableHead>Lücken</TableHead>
            <TableHead>Updates</TableHead><TableHead>Gerät in EX0</TableHead>
          </TableRow></TableHeader>
          <TableBody>
            {machines.map((x: PatchMachine) => (
              <TableRow key={x.endpointId} className={x.deviceId ? "" : "bg-muted/40"}>
                <TableCell className="font-medium">
                  {x.name}
                  <div className="text-xs text-muted-foreground">Inventur <Ago t={x.inventoried} /></div>
                </TableCell>
                <TableCell>
                  <Badge variant={x.online ? "outline" : "secondary"}>{x.online ? "verbunden" : "offline"}</Badge>
                  <div className="text-xs text-muted-foreground"><Ago t={x.lastSeen} /></div>
                </TableCell>
                <TableCell>
                  {x.cveCount === 0 ? <span className="text-muted-foreground">—</span> : (
                    <Badge variant={x.kev || x.worstCvss >= 7 ? "destructive" : "secondary"}>
                      {x.cveCount}{x.worstCvss > 0 ? ` · bis ${x.worstCvss.toFixed(1)}` : ""}{x.kev ? " · ausgenutzt" : ""}
                    </Badge>
                  )}
                </TableCell>
                <TableCell>{x.pending || <span className="text-muted-foreground">—</span>}</TableCell>
                <TableCell>
                  {x.deviceId && open !== x.endpointId ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <Link to={`/devices/${x.deviceId}?tab=patch`} className="underline">{x.deviceName || x.deviceId}</Link>
                      {x.pinned && <Badge variant="secondary">von Hand</Badge>}
                      <Button size="sm" variant="ghost" onClick={() => setOpen(x.endpointId)}>ändern</Button>
                    </div>
                  ) : (
                    <div className="flex flex-wrap items-center gap-2">
                      <Select defaultValue={x.deviceId || NONE} onValueChange={(v) => m.mutate({ endpoint: x.endpointId, device: v === NONE ? "" : v })}>
                        <SelectTrigger className="w-64"><SelectValue placeholder="Gerät wählen" /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NONE}>— kein Gerät —</SelectItem>
                          {devices.map((d) => (
                            <SelectItem key={d.id} value={d.id}>{d.name}{d.ip ? ` · ${d.ip}` : ""}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      {open === x.endpointId && <Button size="sm" variant="ghost" onClick={() => setOpen(undefined)}>abbrechen</Button>}
                    </div>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
