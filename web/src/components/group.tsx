import { useState, type ReactNode } from "react"
import { ChevronRight } from "lucide-react"
import { cn } from "@/lib/utils"

// A list that stays readable at fifty customers: one collapsible block per
// customer, the ones that need attention open, the quiet ones folded away.
export function Group({ title, meta, tone, open, onToggle, children }: {
  title: ReactNode; meta?: ReactNode; tone?: "bad" | "plain"; open: boolean; onToggle: () => void; children: ReactNode
}) {
  return (
    <section className={cn("overflow-hidden rounded-md border", tone === "bad" && "border-destructive/40")}>
      <button type="button" onClick={onToggle} aria-expanded={open}
        className="flex w-full items-center gap-2 bg-muted/40 px-3 py-2 text-left transition-colors hover:bg-muted/70">
        <ChevronRight className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")} />
        <span className="min-w-0 flex-1 truncate font-medium">{title}</span>
        {meta && <span className="shrink-0 text-xs text-muted-foreground">{meta}</span>}
      </button>
      {open && <div className="border-t">{children}</div>}
    </section>
  )
}

/** Which groups are open: everything that needs attention, plus what the user opened. */
export function useGroups(initiallyOpen: string[]) {
  const [manual, setManual] = useState<Record<string, boolean>>({})
  const isOpen = (id: string) => manual[id] ?? initiallyOpen.includes(id)
  const toggle = (id: string) => setManual((m) => ({ ...m, [id]: !isOpen(id) }))
  const setAll = (open: boolean, ids: string[]) => setManual(Object.fromEntries(ids.map((id) => [id, open])))
  return { isOpen, toggle, setAll }
}
