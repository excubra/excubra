import type { ReactNode } from "react"
import { Link } from "react-router"
import { Card, CardAction, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"

// The four-at-the-top card of the shadcn dashboard: description, big number, a badge on
// the right, two footer lines. `tone` tints the gradient: ok (green) or bad (red).
export function StatCard({ label, value, badge, line1, line2, tone, to }: { label: string; value: ReactNode; badge?: ReactNode; line1: ReactNode; line2?: ReactNode; tone?: "ok" | "bad"; to?: string }) {
  const card = (
    <Card className={cn("@container/card h-full", tone === "bad" ? "from-destructive/5 to-card bg-gradient-to-t" : "from-primary/5 to-card bg-gradient-to-t", to && "transition-colors hover:border-input")}>
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <CardTitle className={cn("text-2xl font-semibold tabular-nums @[250px]/card:text-3xl", tone === "bad" && "text-destructive", tone === "ok" && "text-primary")}>{value}</CardTitle>
        {badge && <CardAction>{badge}</CardAction>}
      </CardHeader>
      <CardFooter className="flex-col items-start gap-1.5 text-sm">
        <div className="line-clamp-1 flex gap-2 font-medium">{line1}</div>
        {line2 && <div className="text-muted-foreground">{line2}</div>}
      </CardFooter>
    </Card>
  )
  return to ? <Link to={to} className="block h-full">{card}</Link> : card
}

export function StatGrid({ children }: { children: ReactNode }) {
  return <div className="grid grid-cols-1 gap-4 @xl/main:grid-cols-2 @5xl/main:grid-cols-4">{children}</div>
}
