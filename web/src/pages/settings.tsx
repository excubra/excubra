import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { get, post, type AISettings, type NetbirdSettings } from "@/lib/api"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

// Server-side settings an operator edits rarely: today the technicians' NetBird stack.
export default function SettingsPage() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["settings-netbird"], queryFn: () => get<{ available: boolean; settings?: NetbirdSettings }>("/api/settings/netbird") })
  const qa = useQuery({ queryKey: ["settings-ai"], queryFn: () => get<{ available: boolean; settings?: AISettings }>("/api/settings/ai") })
  const qv = useQuery({ queryKey: ["settings-vuln"], queryFn: () => get<{ available: boolean; hasKey?: boolean }>("/api/settings/vuln") })
  const d = q.data
  const a = qa.data
  const v = qv.data
  if (!d || !a || !v) return <Skeleton className="h-64" />
  return (
    <>
      <PageHeader crumbs={[{ label: "Einstellungen" }]} title="Einstellungen" sub="Was der Server über unsere eigene Infrastruktur wissen muss. Zugangsdaten von Kundengeräten stehen nicht hier, die liegen versiegelt bei den Boxen." />
      <div className="flex flex-col gap-4">
        {a.available && a.settings ? <AIForm s={a.settings} onSaved={() => qc.invalidateQueries({ queryKey: ["settings-ai"] })} /> : null}
        {v.available ? <VulnForm hasKey={!!v.hasKey} onSaved={() => qc.invalidateQueries({ queryKey: ["settings-vuln"] })} /> : null}
        {d.available && d.settings ? <NetbirdForm s={d.settings} onSaved={() => qc.invalidateQueries({ queryKey: ["settings-netbird"] })} /> : <p className="text-sm text-muted-foreground">Fernzugriff ist auf diesem Server nicht aktiv.</p>}
      </div>
    </>
  )
}

function AIForm({ s, onSaved }: { s: AISettings; onSaved: () => void }) {
  const [provider, setProvider] = useState(s.provider || "off")
  const [url, setUrl] = useState(s.url)
  const [model, setModel] = useState(s.model)
  const [key, setKey] = useState("")
  const m = useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post(path, form),
    onSuccess: (r) => { toast.success(r.message); setKey(""); onSaved() },
    onError: (e) => toast.error(e.message),
  })
  return (
    <Card>
      <CardHeader>
        <CardTitle>KI-Auswertung</CardTitle>
        <CardDescription>Das Modell, das die Lagebilder liest (ADR-0019). Anthropic über die Messages-API, oder alles, was die OpenAI-Chat-Schnittstelle spricht, zum Beispiel ein Ollama im Haus. Der Schlüssel wird nie wieder angezeigt.{s.hasKey ? " Ein Schlüssel ist hinterlegt." : " Noch kein Schlüssel hinterlegt."} Je Kunde entscheidet der Schalter auf der Kundenseite, ob überhaupt etwas an das Modell geht.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4 @3xl/main:grid-cols-2">
        <div className="grid gap-2"><Label>Anbieter</Label><Select value={provider} onValueChange={setProvider}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="anthropic">Anthropic</SelectItem><SelectItem value="openai">OpenAI-kompatibel (Ollama, OpenAI, …)</SelectItem><SelectItem value="off">aus</SelectItem></SelectContent></Select></div>
        <div className="grid gap-2"><Label htmlFor="ai-model">Modell</Label><Input id="ai-model" value={model} onChange={(e) => setModel(e.target.value)} placeholder={provider === "anthropic" ? "claude-fable-5-1" : "gpt-oss:120b"} className="font-mono" /></div>
        <div className="grid gap-2"><Label htmlFor="ai-url">Basis-URL (leer = Standard des Anbieters)</Label><Input id="ai-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder={provider === "anthropic" ? "https://api.anthropic.com" : "http://127.0.0.1:11434"} className="font-mono" /></div>
        <div className="grid gap-2"><Label htmlFor="ai-key">API-Schlüssel{s.hasKey ? " (leer lassen = unverändert)" : ""}</Label><Input id="ai-key" type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} className="font-mono" /></div>
        <div className="flex items-end gap-2">
          <Button onClick={() => m.mutate({ path: "/api/settings/ai", form: { provider, url, model, key } })} disabled={m.isPending}>Speichern</Button>
          <Button variant="outline" onClick={() => m.mutate({ path: "/api/settings/ai/test" })} disabled={m.isPending || provider === "off"}>Verbindung prüfen</Button>
        </div>
      </CardContent>
    </Card>
  )
}

function VulnForm({ hasKey, onSaved }: { hasKey: boolean; onSaved: () => void }) {
  const [key, setKey] = useState("")
  const m = useMutation({
    mutationFn: (form: Record<string, string>) => post("/api/settings/vuln", form),
    onSuccess: (r) => { toast.success(r.message); setKey(""); onSaved() },
    onError: (e) => toast.error(e.message),
  })
  return (
    <Card>
      <CardHeader>
        <CardTitle>Schwachstellen-Datenbanken</CardTitle>
        <CardDescription>Jede Version, die der Scan oder ein Konnektor erkennt, wird gegen NVD (Upstream), OSV (Debian- und Ubuntu-Pakete, mit zurückportierten Fixes) und die CISA-Liste der aktiv ausgenutzten Lücken gehalten; Findings der Quelle „CVE-Abgleich“. Läuft ohne Schlüssel, dann erlaubt NVD fünf Anfragen pro halbe Minute. Ein kostenloser NVD-Schlüssel (nvd.nist.gov/developers/request-an-api-key) macht es zehnmal schneller.{hasKey ? " Ein Schlüssel ist hinterlegt." : " Noch kein Schlüssel hinterlegt."}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap items-end gap-2">
        <div className="grid gap-2"><Label htmlFor="nvd-key">NVD-API-Schlüssel</Label><Input id="nvd-key" type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} className="w-80 font-mono" /></div>
        <Button onClick={() => m.mutate({ key })} disabled={m.isPending || !key}>Speichern</Button>
        {hasKey && <Button variant="outline" onClick={() => m.mutate({ clear: "1" })} disabled={m.isPending}>Schlüssel entfernen</Button>}
      </CardContent>
    </Card>
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
