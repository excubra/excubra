import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Star } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { post, type Me } from "@/lib/api"

// The star that puts a customer or a site at the top of the sidebar. It is per
// operator, because whose day it is decides what belongs in reach.
export function PinButton({ kind, id, me, className }: { kind: "tenant" | "site"; id: string; me?: Me; className?: string }) {
  const qc = useQueryClient()
  const pinned = (me?.pins ?? []).some((p) => p.kind === kind && p.id === id)
  const m = useMutation({
    mutationFn: () => post("/api/pins", { kind, id }),
    onSuccess: (r) => { toast.success(r.message); qc.invalidateQueries({ queryKey: ["me"] }) },
    onError: (e) => toast.error(e.message),
  })
  return (
    <Button variant="outline" size="sm" disabled={m.isPending} onClick={() => m.mutate()} className={className}
      aria-pressed={pinned} title={pinned ? "Nicht mehr anheften" : "Oben in der Seitenleiste anheften"}>
      <Star className={cn("size-4", pinned && "fill-primary text-primary")} />
      {pinned ? "Angeheftet" : "Anheften"}
    </Button>
  )
}
