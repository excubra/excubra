import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { get, post, type NetbirdSettings } from "@/lib/api"

// Server-side settings an operator edits rarely: today the technicians' NetBird stack.
export default function SettingsPage() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["settings-netbird"], queryFn: () => get<{ available: boolean; settings?: NetbirdSettings }>("/api/settings/netbird") })
  const d = q.data
  if (!d) return <Skeleton className="h-64" />
  return (
    <>
      <PageHeader crumbs={[{ label: "Einstellungen" }]} title="Einstellungen" sub="Was der Server über unsere eigene Infrastruktur wissen muss. Zugangsdaten von Kundengeräten stehen nicht hier, die liegen versiegelt bei den Boxen." />
      {d.available && d.settings ? <NetbirdForm s={d.settings} onSaved={() => qc.invalidateQueries({ queryKey: ["settings-netbird"] })} /> : <p className="text-sm text-muted-foreground">Fernzugriff ist auf diesem Server nicht aktiv.</p>}
    </>
  )
}

function NetbirdForm({ s, onSaved }: { s: NetbirdSettings; onSaved: () => void }) {
  const [url, setUrl] = useState(s.url)
  const [token, setToken] = useState("")
  const [tech, setTech] = useState(s.techGroup)
  const [lan, setLan] = useState(s.lanGroup)
  const [box, setBox] = useState(s.boxGroup)
  const m = useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post(path, form),
    onSuccess: (r) => { toast.success(r.message); setToken(""); onSaved() },
    onError: (e) => toast.error(e.message),
  })
  return (
    <Card>
      <CardHeader>
        <CardTitle>Techniker-Stack (NetBird)</CardTitle>
        <CardDescription>Der NetBird-Stack, in dem die Techniker sind. EX0 legt dort je Standort Netzwerk, Ressource und Router an, wenn der Fernzugriff eingeschaltet wird. Der API-Token gehört einem eigenen Admin-Benutzer des Stacks und lässt sich dort jederzeit widerrufen.{s.hasToken ? " Ein Token ist hinterlegt." : " Noch kein Token hinterlegt."}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4 @3xl/main:grid-cols-2">
        <div className="grid gap-2"><Label htmlFor="nb-url">Management-URL</Label><Input id="nb-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://viico.vpn.example.test" className="font-mono" /></div>
        <div className="grid gap-2"><Label htmlFor="nb-token">API-Token{s.hasToken ? " (leer lassen = unverändert)" : ""}</Label><Input id="nb-token" type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} className="font-mono" /></div>
        <div className="grid gap-2"><Label htmlFor="nb-tech">Gruppe der Techniker</Label><Input id="nb-tech" value={tech} onChange={(e) => setTech(e.target.value)} className="font-mono" /></div>
        <div className="grid gap-2"><Label htmlFor="nb-lan">Gruppe der Kunden-LANs</Label><Input id="nb-lan" value={lan} onChange={(e) => setLan(e.target.value)} className="font-mono" /></div>
        <div className="grid gap-2"><Label htmlFor="nb-box">Gruppe der Boxen</Label><Input id="nb-box" value={box} onChange={(e) => setBox(e.target.value)} className="font-mono" /></div>
        <div className="flex items-end gap-2">
          <Button onClick={() => m.mutate({ path: "/api/settings/netbird", form: { url, token, tech_group: tech, lan_group: lan, box_group: box } })} disabled={m.isPending}>Speichern</Button>
          <Button variant="outline" onClick={() => m.mutate({ path: "/api/settings/netbird/test" })} disabled={m.isPending || !s.hasToken}>Verbindung prüfen</Button>
        </div>
      </CardContent>
    </Card>
  )
}
