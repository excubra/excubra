import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts"
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { pct } from "@/lib/format"
import type { ChartData } from "@/lib/api"

const config = {
  ok: { label: "erreichbar", color: "var(--chart-1)" },
  failed: { label: "ausgefallen", color: "var(--chart-2)" },
} satisfies ChartConfig

export function AvailabilityChart({ chart, range, onRange, title = "Erreichbarkeit" }: { chart: ChartData; range: string; onRange: (r: string) => void; title?: string }) {
  const data = (chart.Buckets ?? []).map((b) => ({ label: b.Label, ok: b.OK, failed: b.Failed }))
  return (
    <Card className="pt-0">
      <CardHeader className="flex items-center gap-2 space-y-0 border-b py-5 sm:flex-row">
        <div className="grid flex-1 gap-1">
          <CardTitle>{title}</CardTitle>
          <CardDescription>{range === "7d" ? "Prüfungen je Tag, letzte 7 Tage" : "Prüfungen je Stunde, letzte 24 Stunden"} · {chart.Hosts} Hosts · {pct(chart.Pct)} % erreichbar</CardDescription>
        </div>
        <CardAction>
          <ToggleGroup type="single" value={range} onValueChange={(v) => v && onRange(v)} variant="outline" size="sm">
            <ToggleGroupItem value="24h">24 h</ToggleGroupItem>
            <ToggleGroupItem value="7d">7 Tage</ToggleGroupItem>
          </ToggleGroup>
        </CardAction>
      </CardHeader>
      <CardContent className="px-2 pt-4 sm:px-6 sm:pt-6">
        {chart.Rounds === 0 ? (
          <div className="flex h-[250px] items-center justify-center text-sm text-muted-foreground">Noch keine Prüfungen in diesem Zeitraum. Sobald Geräte beobachtet werden, füllt sich die Kurve.</div>
        ) : (
          <ChartContainer config={config} className="aspect-auto h-[250px] w-full">
            <AreaChart data={data} margin={{ left: 8, right: 8 }}>
              <defs>
                <linearGradient id="fillOk" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--color-ok)" stopOpacity={0.8} /><stop offset="95%" stopColor="var(--color-ok)" stopOpacity={0.1} /></linearGradient>
                <linearGradient id="fillFailed" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--color-failed)" stopOpacity={0.8} /><stop offset="95%" stopColor="var(--color-failed)" stopOpacity={0.1} /></linearGradient>
              </defs>
              <CartesianGrid vertical={false} strokeDasharray="3 3" />
              <XAxis dataKey="label" tickLine={false} axisLine={false} tickMargin={8} minTickGap={32} />
              <YAxis hide />
              <ChartTooltip cursor={false} content={<ChartTooltipContent indicator="dot" />} />
              <Area dataKey="failed" type="natural" fill="url(#fillFailed)" stroke="var(--color-failed)" stackId="a" />
              <Area dataKey="ok" type="natural" fill="url(#fillOk)" stroke="var(--color-ok)" stackId="a" />
              <ChartLegend content={<ChartLegendContent />} />
            </AreaChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  )
}
