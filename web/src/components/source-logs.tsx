import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { FileText, ScrollText } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Ago } from "@/components/clock"
import { get, type DeviceLogs, type LogRow } from "@/lib/api"
import { fmtDateTime, fmtShort } from "@/lib/format"

// The families of the contract (ADR-0023 §3). A family matches its kind and
// every sub-kind: "auth" is auth.refused, auth.emergency, auth.device.new, …
const families: { value: string; label: string }[] = [
  { value: "all", label: "Alle Arten" },
  { value: "auth", label: "Anmeldung" },
  { value: "user", label: "Benutzer" },
  { value: "settings", label: "Einstellungen" },
  { value: "hr", label: "Personal" },
  { value: "access", label: "Verweigert" },
  { value: "download", label: "Downloads" },
  { value: "link", label: "Öffentliche Links" },
]

// What the rules (rules/app.go) always call urgent, and what they judge at all.
// Everything else is kept and shown, judged by nobody.
const urgent = new Set(["auth.emergency", "user.admin", "settings.bank"])
const judged = new Set(["auth.refused", "auth.device.new", "user.closed", "settings.secret", "hr.viewed", "access.denied", "download", "link.brake"])

function kindVariant(kind: string): "destructive" | "secondary" | "outline" {
  if (urgent.has(kind)) return "destructive"
  if (judged.has(kind)) return "secondary"
  return "outline"
}

const LIMIT = 500

/** What an application reported about itself (ADR-0023): newest first, live while the tab is open. */
export function SourceLogs({ deviceId, note }: { deviceId: string; note: string }) {
  const [family, setFamily] = useState("all")
  const [days, setDays] = useState("7")
  const [filter, setFilter] = useState("")
  const q = useQuery({
    queryKey: ["device-logs", deviceId, family, days],
    queryFn: () => get<DeviceLogs>(`/api/devices/${deviceId}/logs`, { kind: family === "all" ? undefined : family, days }),
    refetchInterval: 30_000,
  })

  if (q.isLoading) return <Skeleton className="h-64" />
  const d = q.data
  if (!d) return null
  const entries = d.entries ?? []

  if (!d.source && entries.length === 0) {
    return (
      <Empty className="border">
        <EmptyHeader>
          <EmptyMedia variant="icon"><FileText /></EmptyMedia>
          <EmptyTitle>Dieses Gerät schickt keine Logs</EmptyTitle>
          <EmptyDescription>{note}</EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  const needle = filter.trim().toLowerCase()
  const shown = needle
    ? entries.filter((e) => [e.kind, e.actor, e.ip, e.target, e.summary].join(" ").toLowerCase().includes(needle))
    : entries

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><ScrollText className="size-4" />Was die Anwendung meldet</CardTitle>
        <CardDescription>
          Letzter Kontakt <Ago t={d.lastContact} />. Die Anwendung schickt ihre Ereignisse selbst; was die Regeln daraus machen, steht unter Prävention.
          {entries.length >= LIMIT ? ` Gezeigt werden die neuesten ${LIMIT} — für ältere den Zeitraum verkleinern oder nach Art filtern.` : ""}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Select value={family} onValueChange={setFamily}>
            <SelectTrigger className="w-full sm:w-52" aria-label="Art"><SelectValue /></SelectTrigger>
            <SelectContent>{families.map((f) => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}</SelectContent>
          </Select>
          <Select value={days} onValueChange={setDays}>
            <SelectTrigger className="w-full sm:w-40" aria-label="Zeitraum"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="1">Letzter Tag</SelectItem>
              <SelectItem value="7">7 Tage</SelectItem>
              <SelectItem value="30">30 Tage</SelectItem>
              <SelectItem value="90">90 Tage</SelectItem>
            </SelectContent>
          </Select>
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Person, Adresse, Text" className="w-full sm:w-72" />
          <span className="ml-auto font-mono text-xs tabular-nums text-muted-foreground">{shown.length} Einträge</span>
        </div>
        <div className="max-h-[36rem] overflow-auto rounded-md border">
          <Table>
            <TableHeader><TableRow>
              <TableHead>Zeit</TableHead><TableHead>Art</TableHead><TableHead>Wer</TableHead>
              <TableHead>Adresse</TableHead><TableHead>Betroffen</TableHead><TableHead>Was</TableHead>
            </TableRow></TableHeader>
            <TableBody>
              {shown.length === 0 ? (
                <TableRow><TableCell colSpan={6} className="text-muted-foreground">
                  {entries.length === 0 ? `In ${d.days === 1 ? "diesem Tag" : `diesen ${d.days} Tagen`} nichts gemeldet.` : "Nichts gefunden."}
                </TableCell></TableRow>
              ) : shown.map((e: LogRow) => (
                <TableRow key={e.eventId}>
                  <TableCell className="whitespace-nowrap font-mono text-xs tabular-nums" title={`angekommen ${fmtDateTime(e.receivedAt)}`}>{fmtShort(e.occurredAt)}</TableCell>
                  <TableCell><Badge variant={kindVariant(e.kind)} className="font-mono">{e.kind}</Badge></TableCell>
                  <TableCell className="max-w-56 truncate" title={e.actor}>{e.actor || "—"}</TableCell>
                  <TableCell className="font-mono text-xs">{e.ip || "—"}</TableCell>
                  <TableCell className="max-w-56 truncate" title={e.target}>{e.target || "—"}</TableCell>
                  <TableCell className="min-w-64 text-muted-foreground">{e.summary || "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}
