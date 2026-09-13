import { useMemo, useState } from "react"
import { Link, useNavigate, useSearchParams } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { ChevronsDownUp, ChevronsUpDown, List, Map as MapIcon, MapPin, Search, X } from "lucide-react"
import { PageHeader } from "@/components/page-header"
import { Group, useGroups } from "@/components/group"
import { SiteMap, type MapPoint } from "@/components/site-map"
import { StateBadge } from "@/components/status"
import { Ago } from "@/components/clock"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { get, type Me, type SiteRow } from "@/lib/api"

// How bad is it: the sort key that puts what needs a person on top.
const rank = (r: SiteRow) => (!r.HasBox ? 1 : !r.Online ? 3 : r.Down > 0 ? 2 : 0)

// The same four states the badges use, so a marker on the map and a badge in the
// list never disagree about a site.
const tone = (r: SiteRow): MapPoint["tone"] => (!r.HasBox ? "none" : !r.Online ? "silent" : r.Down > 0 ? "bad" : "ok")

export default function SitesPage() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const view = params.get("view") === "karte" ? "karte" : "liste"
  const setView = (v: string) => { const p = new URLSearchParams(params); if (v === "karte") p.set("view", v); else p.delete("view"); setParams(p, { replace: true }) }
  const q = useQuery({ queryKey: ["sites"], queryFn: () => get<SiteRow[]>("/api/sites"), refetchInterval: 30_000 })
  const me = useQuery({ queryKey: ["me"], queryFn: () => get<Me>("/api/me") })
  const [filter, setFilter] = useState("")
  const [picked, setPicked] = useState<string>()
  const rows = useMemo(() => q.data ?? [], [q.data])

  const matching = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    if (!needle) return rows
    return rows.filter((r) => `${r.Site.Name} ${r.Tenant.Name} ${r.Box?.Name ?? ""} ${r.Box?.ID ?? ""} ${r.Site.Address ?? ""}`.toLowerCase().includes(needle))
  }, [rows, filter])

  const groups = useMemo(() => {
    const byTenant = new Map<string, { name: string; sites: SiteRow[] }>()
    for (const r of matching) {
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
  }, [matching])

  // open what needs attention, and everything while searching
  const alwaysOpen = filter.trim() ? groups.map((g) => g.id) : groups.filter((g) => g.trouble > 0 || g.findings > 0).map((g) => g.id)
  const { isOpen, toggle, setAll } = useGroups(alwaysOpen)
  const ids = groups.map((g) => g.id)
  const allOpen = ids.length > 0 && ids.every(isOpen)
  const totalTrouble = groups.reduce((a, g) => a + g.trouble, 0)

  const points: MapPoint[] = useMemo(() => matching
    .filter((r) => r.Site.Located && typeof r.Site.Lat === "number" && typeof r.Site.Lon === "number")
    .map((r) => ({ id: r.Site.ID, name: r.Site.Name, tenant: r.Tenant.Name, lat: r.Site.Lat as number, lon: r.Site.Lon as number, tone: tone(r) })), [matching])
  const unplaced = matching.length - points.length
  const chosen = picked ? matching.find((r) => r.Site.ID === picked) : undefined

  return (
    <>
      <PageHeader
        crumbs={[{ label: "Standorte" }]}
        title="Standorte"
        sub={rows.length
          ? <>{rows.length} Standorte bei {new Set(rows.map((r) => r.Tenant.ID)).size} Kunden · {totalTrouble ? <span className="text-destructive">{totalTrouble} mit Störung</span> : "alle ruhig"}. Nach Kunde gruppiert, Störungen zuerst.</>
          : "Jeder Standort, nach Kunde gruppiert. Suchen, aufklappen, hinein."}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ToggleGroup type="single" value={view} onValueChange={(v) => v && setView(v)} variant="outline" size="sm">
              <ToggleGroupItem value="liste" aria-label="Liste"><List />Liste</ToggleGroupItem>
              <ToggleGroupItem value="karte" aria-label="Karte"><MapIcon />Karte</ToggleGroupItem>
            </ToggleGroup>
            {view === "liste" && ids.length > 1 && (
              <Button variant="outline" size="sm" onClick={() => setAll(!allOpen, ids)}>{allOpen ? <><ChevronsDownUp />Alle zuklappen</> : <><ChevronsUpDown />Alle aufklappen</>}</Button>
            )}
          </div>
        }
      />

      <div className="relative w-full sm:w-80">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Standort, Kunde, Box oder Adresse" className="h-9 w-full pl-8" />
      </div>

      {view === "karte" ? (
        q.isLoading ? <Skeleton className="h-96" /> : points.length === 0 ? (
          <Empty className="border"><EmptyHeader><EmptyTitle>Noch nichts auf der Karte</EmptyTitle>
            <EmptyDescription>
              Ein Standort erscheint hier, sobald er eine Adresse hat. Die trägt man auf der Standort-Seite ein, unter <span className="font-medium">Adresse</span>; die Koordinaten sucht die Konsole einmal und merkt sie sich.
              {rows.length > 0 && <> {rows.length} Standort{rows.length === 1 ? "" : "e"} warten darauf.</>}
            </EmptyDescription></EmptyHeader></Empty>
        ) : (
          <div className="flex flex-col gap-3">
            {/* The chosen site sits on the map, the way a map app does it: what you
                clicked and what it says belong in one frame, not one above the fold
                and one below it. */}
            <div className="relative">
              <SiteMap
                points={points}
                tiles={me.data?.map?.tiles}
                attribution={me.data?.map?.attribution}
                selected={picked}
                onSelect={setPicked}
                className="h-[min(70vh,680px)]"
              />
              {chosen && (
                <div className="pointer-events-none absolute inset-x-2 bottom-8 z-[1000] flex sm:inset-x-auto sm:left-3 sm:max-w-sm">
                  <div className="pointer-events-auto w-full rounded-md border bg-background/95 p-3 shadow-lg backdrop-blur">
                    <div className="flex items-start gap-2">
                      <div className="min-w-0 flex-1">
                        <Link to={`/sites/${chosen.Site.ID}`} className="font-medium hover:underline">{chosen.Site.Name}</Link>
                        <p className="truncate text-xs text-muted-foreground">{chosen.Tenant.Name}</p>
                      </div>
                      <Button variant="ghost" size="icon" className="size-7 shrink-0" aria-label="Schließen" onClick={() => setPicked(undefined)}><X /></Button>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      {!chosen.HasBox ? <Badge variant="secondary">ohne Box</Badge>
                        : !chosen.Online ? <StateBadge cls="silent" label="Box schweigt" />
                          : chosen.Down ? <StateBadge cls="down" label={`${chosen.Down} ausgefallen`} />
                            : <StateBadge cls="ok" label="online" />}
                      {chosen.findings > 0 && <Link to="/findings" className="text-xs font-semibold text-destructive hover:underline">{chosen.findings} Findings</Link>}
                    </div>
                    {chosen.Site.Address && <p className="mt-2 flex items-start gap-1 text-xs text-muted-foreground"><MapPin className="mt-0.5 size-3 shrink-0" />{chosen.Site.Address}</p>}
                    <p className="mt-1 text-xs text-muted-foreground">
                      {chosen.Monitored} beobachtet · {chosen.Devices} Geräte
                      {chosen.HasBox && chosen.Box ? <> · Box <Ago t={chosen.Box.State.LastHeartbeat} /></> : null}
                    </p>
                    <Button size="sm" className="mt-3 w-full" onClick={() => navigate(`/sites/${chosen.Site.ID}`)}>Zum Standort</Button>
                  </div>
                </div>
              )}
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-muted-foreground">
              <span className="flex flex-wrap items-center gap-3">
                <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-full bg-primary" />ruhig</span>
                <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-full bg-destructive" />Störung oder Box schweigt</span>
                <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-full bg-muted-foreground" />ohne Box</span>
              </span>
              {unplaced > 0 && <span>{unplaced} ohne Adresse, nicht auf der Karte</span>}
            </div>
          </div>
        )
      ) : q.isLoading ? <Skeleton className="h-96" /> : groups.length === 0 ? (
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
