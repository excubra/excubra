import { useEffect, useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { MapPin, Search, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { SiteMap } from "@/components/site-map"
import { post, type MapConfig, type Place, type Site } from "@/lib/api"

// Where a site is. The address is what an operator types; the coordinates are
// looked up once, on a click, and then live in the database — so the map draws
// itself without asking anyone anything, and a customer's address is sent to the
// geocoder exactly once in the life of a site.
export function SiteLocationCard({ site, map, onChanged }: { site: Site; map?: MapConfig; onChanged: () => void }) {
  const qc = useQueryClient()
  const [address, setAddress] = useState(site.Address ?? "")
  const [lat, setLat] = useState(site.Located ? String(site.Lat) : "")
  const [lon, setLon] = useState(site.Located ? String(site.Lon) : "")
  const [hits, setHits] = useState<Place[] | null>(null)

  // a different site in the same card (navigation) starts from its own values
  useEffect(() => {
    setAddress(site.Address ?? "")
    setLat(site.Located ? String(site.Lat) : "")
    setLon(site.Located ? String(site.Lon) : "")
    setHits(null)
  }, [site.ID, site.Address, site.Lat, site.Lon, site.Located])

  const search = useMutation({
    mutationFn: () => post<Place[]>(`/api/sites/${site.ID}/geocode`, { address }),
    onSuccess: (places) => {
      setHits(places)
      if (places.length === 1) {
        setLat(String(places[0].lat))
        setLon(String(places[0].lon))
      }
    },
    onError: (e) => toast.error(e.message),
  })

  const save = useMutation({
    mutationFn: (clear?: boolean) => post(`/api/sites/${site.ID}/location`, clear ? { address, lat: "", lon: "" } : { address, lat, lon }),
    onSuccess: (r) => {
      toast.success(r.message)
      setHits(null)
      qc.invalidateQueries({ queryKey: ["site", site.ID] })
      qc.invalidateQueries({ queryKey: ["sites"] })
      onChanged()
    },
    onError: (e) => toast.error(e.message),
  })

  const coords = Number.isFinite(Number(lat)) && Number.isFinite(Number(lon)) && lat !== "" && lon !== ""
  const dirty = address !== (site.Address ?? "") || lat !== (site.Located ? String(site.Lat) : "") || lon !== (site.Located ? String(site.Lon) : "")

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><MapPin className="size-4" />Adresse</CardTitle>
        <CardDescription>
          Wo dieser Standort steht. Mit Adresse erscheint er auf der Karte unter Standorte, und bei einer Störung sieht man auf einen Blick, wo sie ist.
          Die Koordinaten sucht der Server einmal bei OpenStreetMap und merkt sie sich; danach verlässt die Adresse das Haus nicht mehr.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <Label htmlFor={`addr-${site.ID}`}>Straße, PLZ und Ort</Label>
          <div className="flex flex-wrap gap-2">
            <Input id={`addr-${site.ID}`} value={address} onChange={(e) => setAddress(e.target.value)}
              placeholder="Musterweg 1, 12345 Musterstadt" className="min-w-0 flex-1" />
            <Button variant="outline" onClick={() => search.mutate()} disabled={!address.trim() || search.isPending}>
              <Search />{search.isPending ? "sucht …" : "Suchen"}
            </Button>
          </div>
        </div>

        {hits && hits.length > 1 && (
          <div className="flex flex-col gap-1 rounded-md border p-2">
            <p className="px-1 text-xs text-muted-foreground">Mehrere Treffer. Welcher ist es?</p>
            {hits.map((h) => (
              <button key={`${h.lat},${h.lon}`} type="button"
                onClick={() => { setLat(String(h.lat)); setLon(String(h.lon)); setHits(null) }}
                className="rounded px-2 py-1.5 text-left text-sm transition-colors hover:bg-muted/60">
                {h.label}
              </button>
            ))}
          </div>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-2">
            <Label htmlFor={`lat-${site.ID}`}>Breitengrad</Label>
            <Input id={`lat-${site.ID}`} value={lat} onChange={(e) => setLat(e.target.value)} placeholder="52.5163" inputMode="decimal" />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor={`lon-${site.ID}`}>Längengrad</Label>
            <Input id={`lon-${site.ID}`} value={lon} onChange={(e) => setLon(e.target.value)} placeholder="13.3777" inputMode="decimal" />
          </div>
        </div>

        {coords && (
          <SiteMap
            points={[{ id: site.ID, name: site.Name, tenant: "", lat: Number(lat), lon: Number(lon), tone: "ok" }]}
            tiles={map?.tiles ?? ""}
            attribution={map?.attribution ?? ""}
            className="h-56"
          />
        )}

        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={() => save.mutate(undefined)} disabled={!dirty || save.isPending}>Speichern</Button>
          {site.Located && (
            <Button variant="outline" onClick={() => save.mutate(true)} disabled={save.isPending}>
              <Trash2 />Von der Karte nehmen
            </Button>
          )}
          {!coords && address.trim() && <span className="text-sm text-muted-foreground">Ohne Koordinaten wird die Adresse gespeichert, der Standort bleibt aber von der Karte weg.</span>}
        </div>
      </CardContent>
    </Card>
  )
}
