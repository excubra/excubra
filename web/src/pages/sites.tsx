import { useMemo, useState } from "react"
import { Link, useNavigate } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { ChevronsDownUp, ChevronsUpDown, Search } from "lucide-react"
import { PageHeader } from "@/components/page-header"
import { Group, useGroups } from "@/components/group"
import { StateBadge } from "@/components/status"
import { Ago } from "@/components/clock"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type SiteRow } from "@/lib/api"

// How bad is it: the sort key that puts what needs a person on top.
const rank = (r: SiteRow) => (!r.HasBox ? 1 : !r.Online ? 3 : r.Down > 0 ? 2 : 0)

export default function SitesPage() {
  const navigate = useNavigate()
  const q = useQuery({ queryKey: ["sites"], queryFn: () => get<SiteRow[]>("/api/sites"), refetchInterval: 30_000 })
  const [filter, setFilter] = useState("")
  const rows = useMemo(() => q.data ?? [], [q.data])

  const groups = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    const byTenant = new Map<string, { name: string; sites: SiteRow[] }>()
    for (const r of rows) {
      if (needle && !`${r.Site.Name} ${r.Tenant.Name} ${r.Box?.Name ?? ""} ${r.Box?.ID ?? ""}`.toLowerCase().includes(needle)) continue
      const g = byTenant.get(r.Tenant.ID) ?? { name: r.Tenant.Name, sites: [] }
      g.sites.push(r)
      byTenant.set(r.Tenant.ID, g)
    }
    // inside a customer: trouble first, then by name — never an unsorted pile
    const out = [...byTenant.entries()].map(([id, g]) => {
      const sites = [...g.sites].sort((a, b) => rank(b) - rank(a) || a.Site.Name.localeCompare(b.Site.Name, "de"))
      const trouble = sites.filter((s) => rank(s) >= 2).length
      const findings = sites.reduce((a, s) => a + s.findings, 0)
      return { id, name: g.name, sites, trouble, findings }
    })
    return out.sort((a, b) => b.trouble - a.trouble || a.name.localeCompare(b.name, "de"))
  }, [rows, filter])

  // open what needs attention, and everything while searching
  const alwaysOpen = filter.trim() ? groups.map((g) => g.id) : groups.filter((g) => g.trouble > 0 || g.findings > 0).map((g) => g.id)
  const { isOpen, toggle, setAll } = useGroups(alwaysOpen)
  const ids = groups.map((g) => g.id)
  const allOpen = ids.length > 0 && ids.every(isOpen)
  const totalTrouble = groups.reduce((a, g) => a + g.trouble, 0)

  return (
    <>
      <PageHeader
        crumbs={[{ label: "Standorte" }]}
        title="Standorte"
        sub={rows.length
          ? <>{rows.length} Standorte bei {new Set(rows.map((r) => r.Tenant.ID)).size} Kunden · {totalTrouble ? <span className="text-destructive">{totalTrouble} mit Störung</span> : "alle ruhig"}. Nach Kunde gruppiert, Störungen zuerst.</>
          : "Jeder Standort, nach Kunde gruppiert. Suchen, aufklappen, hinein."}
        actions={ids.length > 1 ? <Button variant="outline" size="sm" onClick={() => setAll(!allOpen, ids)}>{allOpen ? <><ChevronsDownUp />Alle zuklappen</> : <><ChevronsUpDown />Alle aufklappen</>}</Button> : undefined}
      />

      <div className="relative w-full sm:w-80">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Standort, Kunde oder Box" className="h-9 w-full pl-8" />
      </div>

      {q.isLoading ? <Skeleton className="h-96" /> : groups.length === 0 ? (
        <Empty className="border"><EmptyHeader><EmptyTitle>{rows.length ? "Nichts gefunden" : "Noch kein Standort"}</EmptyTitle>
          <EmptyDescription>{rows.length ? "Kein Standort passt zur Suche." : <span>Unter <Link className="underline" to="/tenants">Kunden</Link> den ersten Kunden und Standort anlegen.</span>}</EmptyDescription></EmptyHeader></Empty>
      ) : (
        <div className="flex flex-col gap-3">
          {groups.map((g) => (
            <Group key={g.id} open={isOpen(g.id)} onToggle={() => toggle(g.id)} tone={g.trouble ? "bad" : "plain"}
              title={g.name}
              meta={<>{g.sites.length} Standort{g.sites.length === 1 ? "" : "e"}{g.trouble ? <span className="text-destructive"> · {g.trouble} mit Störung</span> : null}{g.findings ? ` · ${g.findings} Findings` : ""}</>}>
              <ul className="divide-y">
                {g.sites.map((s) => (
                  <li key={s.Site.ID}>
                    <button type="button" onClick={() => navigate(`/sites/${s.Site.ID}`)}
                      className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5 text-left transition-colors hover:bg-muted/40">
                      <span className="min-w-0 flex-1 truncate font-medium">{s.Site.Name}</span>
                      {!s.HasBox ? <Badge variant="secondary">ohne Box</Badge>
                        : !s.Online ? <StateBadge cls="silent" label="Box schweigt" />
                          : s.Down ? <StateBadge cls="down" label={`${s.Down} ausgefallen`} />
                            : <StateBadge cls="ok" label="online" />}
                      {s.findings > 0 && <Link to="/findings" onClick={(e) => e.stopPropagation()} className="text-xs font-semibold text-destructive hover:underline">{s.findings} Findings</Link>}
                      <span className="w-full text-xs text-muted-foreground sm:w-auto">
                        {s.Monitored} beobachtet · {s.Devices} Geräte
                        {s.HasBox && s.Box ? <> · Box <Ago t={s.Box.State.LastHeartbeat} /></> : null}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </Group>
          ))}
        </div>
      )}
    </>
  )
}
