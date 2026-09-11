import { useEffect, useState } from "react"
import { useNavigate } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { Box, Building2, MapPin, Monitor, Radar } from "lucide-react"
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command"
import { get, type SearchHit } from "@/lib/api"

const icons: Record<string, typeof Box> = { tenant: Building2, site: MapPin, device: Monitor, host: Radar, box: Box }
const labels: Record<string, string> = { tenant: "Kunden", site: "Standorte", device: "Geräte", host: "Hosts", box: "Boxen" }

export function CommandMenu({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [q, setQ] = useState("")
  const [debounced, setDebounced] = useState("")
  const navigate = useNavigate()
  useEffect(() => { const t = setTimeout(() => setDebounced(q), 150); return () => clearTimeout(t) }, [q])
  const hits = useQuery({ queryKey: ["search", debounced], queryFn: () => get<SearchHit[]>("/api/search", { q: debounced }), enabled: debounced.length >= 2, refetchInterval: false })
  const groups = new Map<string, SearchHit[]>()
  for (const h of hits.data ?? []) groups.set(h.kind, [...(groups.get(h.kind) ?? []), h])
  const go = (href: string) => { onOpenChange(false); setQ(""); navigate(href) }
  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} title="Suche" description="Kunden, Standorte, Geräte, Boxen">
      <CommandInput placeholder="Kunde, Standort, Gerät, IP, MAC …" value={q} onValueChange={setQ} />
      <CommandList>
        <CommandEmpty>{debounced.length < 2 ? "Mindestens zwei Zeichen." : hits.isLoading ? "Suche …" : "Nichts gefunden."}</CommandEmpty>
        {["tenant", "site", "device", "box", "host"].map((k) => {
          const list = groups.get(k)
          if (!list?.length) return null
          const Icon = icons[k]
          return (
            <CommandGroup key={k} heading={labels[k]}>
              {list.map((h) => (
                <CommandItem key={h.kind + h.id} value={h.kind + h.id + h.title} onSelect={() => go(h.href)}>
                  <Icon className="size-4 text-muted-foreground" />
                  <span>{h.title}</span>
                  <span className="ml-2 truncate text-xs text-muted-foreground">{h.sub}{h.tenant && h.kind !== "tenant" ? ` · ${h.tenant}` : ""}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          )
        })}
        <CommandGroup heading="Seiten">
          {[["/", "Übersicht"], ["/tenants", "Kunden"], ["/events", "Ereignisse"], ["/findings", "Prävention"], ["/boxes", "Boxen"], ["/updates", "Updates"], ["/maintenance", "Wartung"], ["/keys", "Enrollment-Keys"], ["/webhooks", "Webhooks"], ["/tokens", "API-Tokens"], ["/users", "Benutzer"], ["/audit", "Audit-Log"]].map(([to, label]) => (
            <CommandItem key={to} value={"page " + label} onSelect={() => go(to)}>{label}</CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  )
}
