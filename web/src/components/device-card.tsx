import { Link } from "react-router"
import { Card } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { StateBadge } from "@/components/status"
import { KindIcon } from "@/components/kind-icon"
import { Ago } from "@/components/clock"
import { fmtShort } from "@/lib/format"
import { cn } from "@/lib/utils"
import type { DeviceCard } from "@/lib/api"

// The card wall: one fixed-size card per device, the same order on every visit.
export function DeviceCardView({ devices, onToggle, busy }: { devices: DeviceCard[]; onToggle: (d: DeviceCard, on: boolean) => void; busy: boolean }) {
  if (!devices.length) return <div className="rounded-md border p-10 text-center text-sm text-muted-foreground">Kein Gerät passt zum Filter.</div>
  return (
    <div className="grid grid-cols-1 gap-3 @xl/main:grid-cols-2 @4xl/main:grid-cols-3 @6xl/main:grid-cols-4 @[100rem]/main:grid-cols-5 @[120rem]/main:grid-cols-6">
      {devices.map((r) => (
        <Card key={r.ID} className={cn("gap-2 py-4", r.Ignored && "opacity-50", r.Monitored && r.StateClass === "down" && "border-destructive/50")}>
          <div className="flex items-start justify-between gap-2 px-4">
            <span className="flex items-center gap-2 text-xs text-muted-foreground"><KindIcon kind={r.Kind} className={r.Monitored ? "text-primary" : ""} />{r.KindLabel}{r.IsUplink && " · Uplink"}</span>
            {!r.IsBox && <Switch checked={r.Monitored} disabled={!r.IP || busy} onCheckedChange={(on) => onToggle(r, on)} aria-label={`${r.Name} beobachten`} />}
          </div>
          <div className="px-4">
            <div className="flex items-center gap-2">
              <Link to={`/devices/${r.ID}`} className="truncate text-base font-semibold hover:underline">{r.Name}</Link>
              {r.IsBox ? <Badge variant="secondary">diese Box</Badge> : r.Monitored ? <StateBadge cls={r.StateClass} /> : null}
            </div>
            <div className="mt-1 font-mono text-sm">{r.IP || <span className="text-muted-foreground">keine IPv4</span>} <span className="text-xs text-muted-foreground">{r.MAC}</span></div>
          </div>
          <div className="mt-auto flex items-center justify-between gap-2 px-4 text-xs text-muted-foreground">
            <span className="truncate">{r.Vendor || "Hersteller unbekannt"}</span>
            <span className={cn("shrink-0", r.GoneAt && "text-destructive")}>{r.GoneAt ? <>weg seit <Ago t={r.GoneAt} /></> : `seit ${fmtShort(r.FirstSeen)}`}</span>
          </div>
        </Card>
      ))}
    </div>
  )
}
