import { useEffect, useMemo, useRef, useState } from "react"
import L from "leaflet"
import "leaflet/dist/leaflet.css"
import { cn } from "@/lib/utils"

// A map of the sites. It exists because a list answers "which sites are there"
// and fifty rows answer nothing at all; a map answers "where is it burning".
//
// Two deliberate choices. Markers are div icons built from the theme's own
// colours, not Leaflet's default pin, so no image files ship and the map speaks
// the same colour vocabulary as every badge in the console — the marker's markup
// is a fixed template of numbers and CSS variables, never a site's name. And
// clicking a marker opens no popup: it hands the site back to React, which draws
// the card, so customer names reach the page as text nodes like everywhere else.

export type MapPoint = {
  id: string
  name: string
  tenant: string
  lat: number
  lon: number
  /** ok | bad | silent | none — the same vocabulary as StateBadge. */
  tone: "ok" | "bad" | "silent" | "none"
}

/** The marker colours, read from the theme so light and dark both hold. */
const toneVar: Record<MapPoint["tone"], string> = {
  ok: "var(--primary)",
  bad: "var(--destructive)",
  silent: "var(--destructive)",
  none: "var(--muted-foreground)",
}

function pin(p: MapPoint, selected: boolean) {
  const colour = toneVar[p.tone]
  const size = selected ? 26 : 20
  return L.divIcon({
    className: "", // no Leaflet chrome; the span below is the whole marker
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
    html:
      `<span style="display:block;width:${size}px;height:${size}px;border-radius:9999px;` +
      `background:${colour};opacity:.9;` +
      `box-shadow:0 0 0 ${selected ? 4 : 2}px color-mix(in oklab, ${colour} 35%, transparent), 0 1px 3px rgba(0,0,0,.4);"></span>`,
  })
}

export function SiteMap({
  points, tiles, attribution, selected, onSelect, className,
}: {
  points: MapPoint[]
  tiles: string
  attribution: string
  selected?: string
  onSelect?: (id: string) => void
  className?: string
}) {
  const host = useRef<HTMLDivElement>(null)
  const map = useRef<L.Map | null>(null)
  const markers = useRef<Map<string, L.Marker>>(new Map())
  const [ready, setReady] = useState(false)

  // create once
  useEffect(() => {
    if (!host.current || map.current) return
    // No wheel zoom: the map fills most of the page, and a map that swallows the
    // scroll wheel traps everything below it. Zoom with the buttons, a double
    // click, or two fingers.
    const m = L.map(host.current, { attributionControl: true, zoomControl: true, worldCopyJump: true, scrollWheelZoom: false })
    m.setView([51.2, 10.4], 5) // a sensible first frame before the points arrive
    map.current = m
    const drawn = markers.current // the same Map for this effect's whole life
    setReady(true)
    return () => { m.remove(); map.current = null; drawn.clear() }
  }, [])

  // the tile layer, replaced when the operator changes the source
  useEffect(() => {
    const m = map.current
    if (!m || !ready) return
    if (!tiles) return
    const layer = L.tileLayer(tiles, { attribution, maxZoom: 19, className: "ex0-tiles" }).addTo(m)
    return () => { layer.remove() }
  }, [ready, tiles, attribution])

  const key = useMemo(() => points.map((p) => `${p.id}:${p.lat}:${p.lon}:${p.tone}`).join("|"), [points])

  // the markers, rebuilt whenever a site moves or changes colour
  useEffect(() => {
    const m = map.current
    if (!m || !ready) return
    for (const mk of markers.current.values()) mk.remove()
    markers.current.clear()
    for (const p of points) {
      const mk = L.marker([p.lat, p.lon], { icon: pin(p, p.id === selected), title: `${p.name} · ${p.tenant}`, riseOnHover: true })
      mk.on("click", () => onSelect?.(p.id))
      mk.addTo(m)
      markers.current.set(p.id, mk)
    }
    if (points.length > 0) {
      const b = L.latLngBounds(points.map((p) => [p.lat, p.lon] as [number, number]))
      m.fitBounds(b, { padding: [40, 40], maxZoom: points.length === 1 ? 14 : 16 })
    }
    // `key` stands in for the contents of `points`; selection is handled below
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, key])

  // only the selected marker changes, so redraw two icons instead of all of them
  useEffect(() => {
    if (!ready) return
    for (const p of points) {
      const mk = markers.current.get(p.id)
      if (mk) mk.setIcon(pin(p, p.id === selected))
    }
    const mk = selected ? markers.current.get(selected) : undefined
    if (mk) map.current?.panTo(mk.getLatLng())
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, selected, key])

  return <div ref={host} className={cn("ex0-map w-full rounded-md border", className)} style={{ minHeight: 320 }} />
}
