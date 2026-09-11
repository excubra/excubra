import { CheckCircle2, CircleAlert, CircleDashed, Wrench, PauseCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

// One vocabulary for state everywhere: green = alive, red = outage, grey = unknown/waiting.
export function StateBadge({ cls, label, className }: { cls: string; label?: string; className?: string }) {
  const base = "gap-1 font-medium"
  switch (cls) {
    case "up":
    case "ok":
    case "online":
      return <Badge variant="outline" className={cn(base, "border-primary/40 bg-primary/10 text-primary", className)}><CheckCircle2 className="size-3" />{label ?? "erreichbar"}</Badge>
    case "down":
    case "bad":
    case "silent":
      return <Badge variant="outline" className={cn(base, "border-destructive/40 bg-destructive/10 text-destructive", className)}><CircleAlert className="size-3" />{label ?? "ausgefallen"}</Badge>
    case "maint":
      return <Badge variant="outline" className={cn(base, "text-muted-foreground", className)}><Wrench className="size-3" />{label ?? "Wartung"}</Badge>
    case "suppressed":
      return <Badge variant="outline" className={cn(base, "text-muted-foreground", className)}><PauseCircle className="size-3" />{label ?? "unterdrückt"}</Badge>
    default:
      return <Badge variant="outline" className={cn(base, "text-muted-foreground", className)}><CircleDashed className="size-3" />{label ?? "unbekannt"}</Badge>
  }
}

export function Dot({ cls, className }: { cls: string; className?: string }) {
  const color = cls === "up" || cls === "ok" || cls === "online" ? "bg-primary" : cls === "down" || cls === "bad" || cls === "silent" ? "bg-destructive" : "bg-muted-foreground"
  return <span className={cn("inline-block size-2 rounded-full", color, className)} />
}

export function LiveDot({ ok }: { ok: boolean }) {
  return (
    <span className="relative inline-flex size-2.5">
      {ok && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-60" />}
      <span className={cn("relative inline-flex size-2.5 rounded-full", ok ? "bg-primary" : "bg-destructive")} />
    </span>
  )
}

export function boxClass(status: string, lastHeartbeat: string): string {
  if (status === "silent") return "silent"
  if (!lastHeartbeat || lastHeartbeat.startsWith("0001")) return "never"
  return "online"
}
