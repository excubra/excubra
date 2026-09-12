import { useState } from "react"
import { useNavigate } from "react-router"
import { useMutation } from "@tanstack/react-query"
import { toast } from "sonner"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog"
import { Ago } from "@/components/clock"
import { SealFingerprint } from "@/components/seal-fingerprint"
import { post, type BoxRow, type Site } from "@/lib/api"
import { fmtDateTime, gb, humanDur } from "@/lib/format"

function Row({ k, children, mono }: { k: string; children: React.ReactNode; mono?: boolean }) {
  return <div className="grid grid-cols-[140px_1fr] gap-3 text-sm"><span className="text-muted-foreground">{k}</span><span className={mono ? "font-mono text-[13px] break-all" : ""}>{children}</span></div>
}

export function BoxTech({ box, site, sites, tenantNames, fingerprint, netbird, subnets, onChanged }: {
  box: BoxRow; site?: Site; sites: Site[]; tenantNames: Record<string, string>; fingerprint: string; netbird: { ManagementURL: string; ClaimedAt: string | null } | null; subnets: string; onChanged: () => void
}) {
  const navigate = useNavigate()
  const [name, setName] = useState(box.Name)
  const [channel, setChannel] = useState(box.Channel || "stable")
  const [mode, setMode] = useState(box.DiscoveryMode || "sweep")
  const [subs, setSubs] = useState(subnets)
  const [siteId, setSiteId] = useState(site?.ID ?? box.SiteID ?? "")
  const [mgmt, setMgmt] = useState("")
  const [key, setKey] = useState("")
  const m = useMutation({
    mutationFn: ({ path, form }: { path: string; form?: Record<string, string> }) => post(path, form),
    onSuccess: (r, v) => { toast.success(r.message); if (v.path.endsWith("/delete")) navigate("/boxes"); else onChanged() },
    onError: (e) => toast.error(e.message),
  })
  const online = box.State.Status !== "silent" && !box.State.LastHeartbeat.startsWith("0001")
  return (
    <div className="grid gap-4 @4xl/main:grid-cols-2">
      <Card>
        <CardHeader><CardTitle>Box</CardTitle><CardDescription className="font-mono">{box.ID}</CardDescription></CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Row k="Zustand"><Badge variant="outline" className={online ? "border-primary/40 text-primary" : "border-destructive/40 text-destructive"}>{online ? "online" : "schweigt"}</Badge> <span className="text-muted-foreground">Heartbeat <Ago t={box.State.LastHeartbeat} /></span></Row>
          <Row k="Agent">{box.AgentVersion || "–"} · Kanal {box.Channel} · {box.OS}/{box.Arch}</Row>
          <Row k="Techniker-Stack">{box.NetbirdOpStatus === "connected" ? <>verbunden <span className="font-mono text-xs">{box.NetbirdOpIP}</span> <span className="text-muted-foreground">· ssh root@{box.NetbirdOpIP}</span></> : box.NetbirdOpStatus === "not_configured" ? "Operator-Daemon bereit, wartet auf den Schlüssel von EX0" : box.NetbirdOpStatus || <span className="text-muted-foreground">kein Operator-Daemon gemeldet (Box-Image ohne netbird-operator)</span>}</Row>
          <Row k="Kunden-NetBird">{box.NetbirdStatus === "connected" ? <>verbunden <span className="font-mono text-xs">{box.NetbirdIP}</span></> : box.NetbirdStatus === "not_configured" ? <span className="text-muted-foreground">bereit, kein Kunden-VPN (Opt-in: Schlüssel unten hinterlegen)</span> : box.NetbirdStatus || "nicht gemeldet"}</Row>
          <Row k="Platte">{box.DiskTotalBytes ? `${gb(box.DiskFreeBytes)} von ${gb(box.DiskTotalBytes)} GB frei · Uptime ${humanDur(box.UptimeS * 1000)}` : "–"}</Row>
          <Row k="Enrollt">{fmtDateTime(box.EnrolledAt)}</Row>
          <Row k="Hardware" mono>{box.HWID}</Row>
          <Row k="Zertifikat" mono>{box.CertSerial}<div className="font-sans text-xs text-muted-foreground">gültig bis {fmtDateTime(box.CertNotAfter)}, verlängert sich selbst</div></Row>
          <Row k="CA-Fingerprint" mono>{fingerprint}</Row>
          <Row k="Siegelschlüssel"><SealFingerprint sealKey={box.SealKey ?? ""} className="text-[13px]" /><div className="text-xs text-muted-foreground">Zugangsdaten für Geräte-APIs werden im Browser für diesen Schlüssel versiegelt.</div></Row>
          <Row k="LAN der Box">{box.LAN?.length ? <span className="font-mono text-[13px]">{box.LAN.join(", ")}{box.LANIP ? ` · Adresse ${box.LANIP}` : ""}</span> : <span className="text-muted-foreground">noch nicht gemeldet</span>}</Row>
          <Row k="Discovery">{box.DiscoveryMode === "sweep" ? "passiv + ARP-Sweep alle 15 min im eigenen Netz" : "nur passiv"}{box.DiscoverySubnets?.length ? ` · ICMP-Sweep: ${box.DiscoverySubnets.join(", ")}` : ""}</Row>
          <Row k="Köder-Ports">{box.Canary?.length ? <span className="font-mono text-[13px]">{box.Canary.join(", ")}</span> : <span className="text-muted-foreground">keine offen (Live-Erkennung aus, oder Agent vor 0.5)</span>}</Row>
          <Separator />
          <div className="grid gap-2">
            <Label>Zuordnung</Label>
            <div className="flex gap-2">
              <Select value={siteId || "__none"} onValueChange={(v) => setSiteId(v === "__none" ? "" : v)}>
                <SelectTrigger className="flex-1"><SelectValue placeholder="Standort" /></SelectTrigger>
                <SelectContent><SelectItem value="__none">nicht zugeordnet</SelectItem>{sites.map((s) => <SelectItem key={s.ID} value={s.ID}>{tenantNames[s.TenantID]} · {s.Name}</SelectItem>)}</SelectContent>
              </Select>
              <Button variant="outline" onClick={() => m.mutate({ path: `/api/boxes/${box.ID}/assign`, form: { site_id: siteId } })} disabled={m.isPending}>Zuordnen</Button>
            </div>
          </div>
          <Separator />
          <div className="grid gap-2">
            <Label>Kunden-NetBird (Opt-in)</Label>
            {netbird ? (
              <p className="text-sm text-muted-foreground">Hinterlegt für <span className="font-mono">{netbird.ManagementURL}</span>{netbird.ClaimedAt ? `, abgeholt ${fmtDateTime(netbird.ClaimedAt)}` : ", wird beim nächsten Config-Pull einmalig abgeholt"}. <Button variant="link" size="sm" className="h-auto p-0" onClick={() => m.mutate({ path: `/api/boxes/${box.ID}/netbird`, form: { action: "clear" } })}>Entfernen</Button></p>
            ) : <p className="text-sm text-muted-foreground">{box.NetbirdStatus === "connected" ? "Nicht nötig: Die Box ist bereits im Kunden-Stack verbunden." : "Kein Schlüssel hinterlegt. Bekommt der Kunde einen eigenen NetBird-Stack, hier Management-URL und Setup-Key eintragen: Die Box holt ihn genau einmal ab und setzt ihren vorbereiteten Kunden-Peer damit in Betrieb."}</p>}
            <div className="grid gap-2 @xl/main:grid-cols-[1fr_1fr_auto]">
              <Input value={mgmt} onChange={(e) => setMgmt(e.target.value)} placeholder="https://kunde.vpn.example.test" />
              <Input value={key} onChange={(e) => setKey(e.target.value)} placeholder="Setup-Key" autoComplete="off" />
              <Button variant="outline" onClick={() => m.mutate({ path: `/api/boxes/${box.ID}/netbird`, form: { management_url: mgmt, setup_key: key } })} disabled={!mgmt || !key || m.isPending}>Hinterlegen</Button>
            </div>
          </div>
          <Separator />
          <div className="flex flex-wrap gap-2">
            <AlertDialog>
              <AlertDialogTrigger asChild><Button variant="outline" size="sm" className="text-destructive">Zertifikat widerrufen</Button></AlertDialogTrigger>
              <AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Zertifikat sperren?</AlertDialogTitle><AlertDialogDescription>Die Box kann sich danach nicht mehr melden. Für eine neue Box braucht es einen neuen Enrollment-Key.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Abbrechen</AlertDialogCancel><AlertDialogAction onClick={() => m.mutate({ path: `/api/boxes/${box.ID}/revoke` })}>Sperren</AlertDialogAction></AlertDialogFooter></AlertDialogContent>
            </AlertDialog>
            <AlertDialog>
              <AlertDialogTrigger asChild><Button variant="outline" size="sm" className="text-destructive">Box löschen</Button></AlertDialogTrigger>
              <AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Box samt Hosts löschen?</AlertDialogTitle><AlertDialogDescription>Alle beobachteten Hosts dieser Box werden gelöscht. Das Inventar des Standorts bleibt.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Abbrechen</AlertDialogCancel><AlertDialogAction onClick={() => m.mutate({ path: `/api/boxes/${box.ID}/delete` })}>Löschen</AlertDialogAction></AlertDialogFooter></AlertDialogContent>
            </AlertDialog>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>Einstellungen</CardTitle><CardDescription>Die Box holt Änderungen mit dem nächsten Heartbeat.</CardDescription></CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="grid gap-2"><Label htmlFor="bname">Name der Box</Label><Input id="bname" value={name} onChange={(e) => setName(e.target.value)} placeholder="z. B. muster-box" /></div>
          <div className="grid gap-4 @xl/main:grid-cols-2">
            <div className="grid gap-2"><Label>Update-Kanal</Label><Select value={channel} onValueChange={setChannel}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="stable">stable</SelectItem><SelectItem value="canary">canary</SelectItem></SelectContent></Select></div>
            <div className="grid gap-2"><Label>Discovery</Label><Select value={mode} onValueChange={setMode}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="sweep">passiv + Sweep alle 15 min</SelectItem><SelectItem value="passive">nur passiv</SelectItem></SelectContent></Select></div>
          </div>
          <div className="grid gap-2"><Label htmlFor="subs">Weitere Subnetze für den ICMP-Sweep (CIDR je Zeile, max. 8)</Label><Textarea id="subs" rows={3} value={subs} onChange={(e) => setSubs(e.target.value)} placeholder="192.168.101.0/24" /></div>
          <div><Button onClick={() => m.mutate({ path: `/api/boxes/${box.ID}/settings`, form: { name, channel, discovery_mode: mode, discovery_subnets: subs } })} disabled={m.isPending}>Speichern</Button></div>
        </CardContent>
      </Card>
    </div>
  )
}
