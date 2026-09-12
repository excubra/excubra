import { Box, CircleHelp, Globe, Laptop, Monitor, Network, Phone, Printer, Server, Shield, Smartphone } from "lucide-react"
import { cn } from "@/lib/utils"

const map: Record<string, typeof Box> = { fw: Shield, rt: Network, srv: Server, vm: Monitor, tel: Phone, prn: Printer, lap: Laptop, mob: Smartphone, box: Box, wan: Globe, q: CircleHelp }

export function KindIcon({ kind, className }: { kind: string; className?: string }) {
  const Icon = map[kind] ?? CircleHelp
  return <Icon className={cn("size-4 shrink-0", className)} />
}
