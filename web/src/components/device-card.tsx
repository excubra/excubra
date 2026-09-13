import { Link } from "react-router"
import { ConnectIP } from "@/components/connect"
import { Card } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { StateBadge } from "@/components/status"
import { DeviceMark } from "@/components/kind-icon"
import { Ago } from "@/components/clock"
import { fmtShort } from "@/lib/format"
import { cn } from "@/lib/utils"
import type { DeviceCard } from "@/lib/api"

// The card wall: one fixed-size card per device, the same order on every visit.
export function DeviceCardView({ devices, onToggle, busy, onOpen }: {
  devices: DeviceCard[]; onToggle: (d: DeviceCard, on: boolean) => void; busy: boolean; onOpen?: (d: DeviceCard) => void
}) {
  if (!devices.length) return <div className="rounded-md border p-10 text-center text-sm text-muted-foreground">Kein Gerät passt zum Filter.</div>
  return (
    <div className="grid grid-cols-1 gap-3 @xl/main:grid-cols-2 @4xl/main:grid-cols-3 @6xl/main:grid-cols-4 @[100rem]/main:grid-cols-5 @[120rem]/main:grid-cols-6">
      {devices.map((r) => (
        // The whole card is the way into the device; the switch, the address link
        // and the menu inside it keep their own clicks.
        <Card key={r.ID} role={onOpen ? "button" : undefined} tabIndex={onOpen ? 0 : undefined}
          onClick={onOpen ? (e) => { if ((e.target as HTMLElement).closest("button,a,input,[role=switch],[role=menuitem]")) return; onOpen(r) } : undefined}
          onKeyDown={onOpen ? (e) => { if (e.key === "Enter" && e.target === e.currentTarget) onOpen(r) } : undefined}
          className={cn("gap-2 py-4", onOpen && "cursor-pointer transition-colors hover:border-primary/40 focus-visible:ring-2 focus-visible:ring-ring", r.Ignored && "opacity-50", r.Monitored && r.StateClass === "down" && "border-destructive/50")}>
          <div className="flex items-start justify-between gap-2 px-4">
            <span className="flex items-center gap-2 text-xs text-muted-foreground"><DeviceMark kind={r.Kind} vendor={r.Vendor} active={r.Monitored} />{r.KindLabel}{r.IsUplink && " · Uplink"}</span>
            {!r.IsBox && <Switch checked={r.Monitored} disabled={!r.IP || busy} onCheckedChange={(on) => onToggle(r, on)} aria-label={`${r.Name} beobachten`} />}
          </div>
          <div className="px-4">
            <div className="flex items-center gap-2">
              <Link to={`/devices/${r.ID}`} className="truncate text-base font-semibold hover:underline">{r.Name}</Link>
              {r.IsBox ? <Badge variant="secondary">diese Box</Badge> : r.Monitored ? <StateBadge cls={r.StateClass} /> : null}
            </div>
            <div className="mt-1"><ConnectIP kind={r.Kind} ip={r.IP} ports={r.Ports} sub={r.MAC} className="text-sm" /></div>
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
