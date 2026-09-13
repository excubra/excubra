import { Box, CircleHelp, Globe, Laptop, Monitor, Network, Phone, Printer, Server, Shield, Smartphone } from "lucide-react"
import { cn } from "@/lib/utils"
import { VendorMark } from "@/components/vendor-mark"

const map: Record<string, typeof Box> = { fw: Shield, rt: Network, srv: Server, vm: Monitor, tel: Phone, prn: Printer, lap: Laptop, mob: Smartphone, box: Box, wan: Globe, q: CircleHelp }

export function KindIcon({ kind, className }: { kind: string; className?: string }) {
  const Icon = map[kind] ?? CircleHelp
  return <Icon className={cn("size-4 shrink-0", className)} />
}

/** The device's brand mark where the vendor is known, its kind otherwise. */
export function DeviceMark({ kind, vendor, className, active }: { kind: string; vendor?: string; className?: string; active?: boolean }) {
  // Every known vendor gets its own mark — the brand where a CC0 source has it,
  // a monogram where it does not. Only a device whose vendor we never learned
  // falls back to the kind icon.
  if (vendor && vendor.trim() && !/^(hersteller )?unbekannt$/i.test(vendor.trim())) {
    return <VendorMark vendor={vendor} className={cn("size-4 shrink-0", className)} />
  }
  return <KindIcon kind={kind} className={cn(active && "text-primary", className)} />
}
