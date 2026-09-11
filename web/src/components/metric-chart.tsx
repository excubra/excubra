import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts"
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type SamplePoint } from "@/lib/api"
import { fmtShort, fmtTime } from "@/lib/format"

const LABEL: Record<string, string> = {
  cpu_pct: "CPU %", mem_pct: "RAM %", disk_pct: "Platte %", sessions: "Sessions", interfaces_up: "Interfaces up", interfaces_down: "Interfaces down",
  ipsec_up: "Tunnel up", ipsec_down: "Tunnel down", ha_peers: "HA-Partner", licenses_expired: "Lizenzen abgelaufen", users: "Benutzer", phonenumbers: "Rufnummern",
}
const PREFERRED = ["cpu_pct", "mem_pct", "sessions", "ipsec_up", "users"]

// One number of a connector over time. The box samples every few minutes; the
// server keeps the samples per day, the chart asks for 24 hours or 7 days.
export function MetricChart({ connectorId, metrics }: { connectorId: string; metrics: Record<string, number> }) {
  const keys = Object.keys(metrics).filter((k) => LABEL[k]).sort((a, b) => (PREFERRED.indexOf(a) + 100) % 100 - (PREFERRED.indexOf(b) + 100) % 100 || a.localeCompare(b))
  const [key, setKey] = useState(keys[0] ?? "")
  const [range, setRange] = useState("24h")
  const q = useQuery({
    queryKey: ["samples", connectorId, key, range],
    queryFn: () => get<{ key: string; points: SamplePoint[] }>(`/api/connectors/${connectorId}/samples`, { key, range }),
    enabled: key !== "",
    refetchInterval: 60_000,
  })
  if (keys.length === 0) return null
  const data = (q.data?.points ?? []).map((p) => ({ t: p.at, v: p.value }))
  const config = { v: { label: LABEL[key] ?? key, color: "var(--chart-1)" } } satisfies ChartConfig
  return (
    <div className="rounded-md border">
      <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
        <Select value={key} onValueChange={setKey}><SelectTrigger size="sm" className="w-44"><SelectValue /></SelectTrigger><SelectContent>{keys.map((k) => <SelectItem key={k} value={k}>{LABEL[k]}</SelectItem>)}</SelectContent></Select>
        <span className="text-xs text-muted-foreground">{data.length ? `${data.length} Messungen` : q.isLoading ? "lädt …" : "noch keine Messungen im Zeitraum"}</span>
        <ToggleGroup type="single" value={range} onValueChange={(v) => v && setRange(v)} variant="outline" size="sm" className="ml-auto">
          <ToggleGroupItem value="24h">24 h</ToggleGroupItem>
          <ToggleGroupItem value="7d">7 Tage</ToggleGroupItem>
        </ToggleGroup>
      </div>
      <div className="px-2 pt-3 pb-1">
        {q.isLoading ? <Skeleton className="h-[160px] w-full" /> : (
          <ChartContainer config={config} className="aspect-auto h-[160px] w-full">
            <LineChart data={data} margin={{ left: 0, right: 12, top: 4, bottom: 0 }}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickLine={false} axisLine={false} minTickGap={48} tickFormatter={(v) => (range === "7d" ? fmtShort(String(v)) : fmtTime(String(v)))} />
              <YAxis width={44} tickLine={false} axisLine={false} domain={key.endsWith("_pct") ? [0, 100] : ["auto", "auto"]} />
              <ChartTooltip cursor={false} content={<ChartTooltipContent indicator="line" labelFormatter={(v) => fmtShort(String(v))} />} />
              <Line type="monotone" dataKey="v" stroke="var(--color-v)" strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ChartContainer>
        )}
      </div>
    </div>
  )
}
