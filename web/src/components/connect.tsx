import { ChevronDown, ExternalLink } from "lucide-react"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { cn } from "@/lib/utils"

// Getting onto a device should not mean selecting an address, copying it, opening
// a second window and typing a scheme in front of it. The scan already knows which
// ports are open, so the console can offer the way in as a link: the browser opens
// http and https itself, and hands ssh, rdp, vnc and smb to the client the
// operator already has installed.
//
// It works because the box's LAN is routed into the operator overlay — the same
// address the box reports is reachable from the operator's machine.

export type Target = { label: string; href: string; hint: string }

/** What a port means, most useful first. */
const byPort: { ports: number[]; make: (ip: string, port: number) => Target }[] = [
  { ports: [443, 8443, 4443, 9443, 10443], make: (ip, p) => ({ label: "Weboberfläche (HTTPS)", href: `https://${ip}${p === 443 ? "" : `:${p}`}`, hint: "öffnet einen neuen Tab" }) },
  { ports: [80, 8080, 8000, 8008, 8081], make: (ip, p) => ({ label: "Weboberfläche (HTTP)", href: `http://${ip}${p === 80 ? "" : `:${p}`}`, hint: "unverschlüsselt" }) },
  { ports: [3389], make: (ip) => ({ label: "Remotedesktop", href: `rdp://${ip}`, hint: "öffnet den RDP-Client" }) },
  { ports: [22], make: (ip) => ({ label: "SSH", href: `ssh://${ip}`, hint: "öffnet das Terminal" }) },
  { ports: [5900, 5901, 5902], make: (ip, p) => ({ label: "VNC", href: `vnc://${ip}${p === 5900 ? "" : `:${p}`}`, hint: "öffnet den VNC-Client" }) },
  { ports: [445], make: (ip) => ({ label: "Dateifreigabe", href: `smb://${ip}`, hint: "öffnet den Datei-Manager" }) },
  { ports: [21], make: (ip) => ({ label: "FTP", href: `ftp://${ip}`, hint: "unverschlüsselt" }) },
]

/** Devices that have a web interface even when nothing scanned them yet. */
const webByKind = new Set(["fw", "rt", "prn", "tel", "srv", "vm", "box", "nas"])

/**
 * connectTargets lists the ways into a device, best first. With scan results it
 * uses what is actually open; without them it falls back to what the kind of
 * device almost certainly has, marked as a guess.
 */
export function connectTargets(kind: string, ip: string, ports?: number[] | null): Target[] {
  if (!ip) return []
  const open = ports ?? []
  const out: Target[] = []
  const seen = new Set<string>()
  for (const rule of byPort) {
    for (const p of rule.ports) {
      if (!open.includes(p)) continue
      const t = rule.make(ip, p)
      if (seen.has(t.href)) continue
      seen.add(t.href)
      out.push(t)
    }
  }
  if (out.length === 0 && webByKind.has(kind)) {
    out.push(
      { label: "Weboberfläche (HTTPS)", href: `https://${ip}`, hint: "nicht geprüft, üblich bei diesem Gerät" },
      { label: "Weboberfläche (HTTP)", href: `http://${ip}`, hint: "nicht geprüft, unverschlüsselt" },
    )
  }
  return out
}

/**
 * ServicePort renders one scanned port. Where the port is something a client can
 * open, it is the link; otherwise it is the plain "tcp/9100" it always was.
 */
export function ServicePort({ proto, port, ip, gone }: { proto: string; port: number; ip: string; gone?: boolean }) {
  const label = `${proto || "tcp"}/${port}`
  const target = ip && !gone && (proto === "" || proto === "tcp") ? connectTargets("", ip, [port])[0] : undefined
  if (!target) return <span className="font-mono text-xs">{label}</span>
  return (
    <a href={target.href} target="_blank" rel="noreferrer" title={`${target.label} — ${target.hint}`}
      className="font-mono text-xs underline decoration-dotted underline-offset-2 hover:text-primary hover:decoration-solid">
      {label}
    </a>
  )
}

/**
 * ConnectIP renders the address as the way in. One click follows the most likely
 * protocol; the chevron offers the rest. Without a usable target it is plain text,
 * because a link that goes nowhere is worse than none.
 */
export function ConnectIP({ kind, ip, ports, className, sub }: { kind: string; ip: string; ports?: number[] | null; className?: string; sub?: string }) {
  const targets = connectTargets(kind, ip, ports)
  if (!ip) return <span className={cn("text-muted-foreground", className)}>keine IPv4</span>
  if (targets.length === 0) {
    return <span className={cn("font-mono", className)}>{ip}{sub && <span className="block text-xs text-muted-foreground">{sub}</span>}</span>
  }
  const [first, ...rest] = targets
  return (
    <span className={cn("inline-flex items-start gap-1", className)}>
      <span className="min-w-0">
        <a href={first.href} target="_blank" rel="noreferrer" title={`${first.label} — ${first.hint}`}
          onClick={(e) => e.stopPropagation()}
          className="font-mono underline decoration-dotted underline-offset-2 hover:text-primary hover:decoration-solid">
          {ip}
        </a>
        {sub && <span className="block text-xs text-muted-foreground">{sub}</span>}
      </span>
      {rest.length > 0 && (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="size-5 shrink-0 text-muted-foreground" aria-label="Andere Verbindung" onClick={(e) => e.stopPropagation()}>
              <ChevronDown className="size-3" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" onClick={(e) => e.stopPropagation()}>
            <DropdownMenuLabel>Verbinden mit {ip}</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {targets.map((t) => (
              <DropdownMenuItem key={t.href} asChild>
                <a href={t.href} target="_blank" rel="noreferrer" className="flex items-center gap-2">
                  <ExternalLink className="size-3.5" />
                  <span className="flex-1">{t.label}</span>
                  <span className="text-xs text-muted-foreground">{t.hint}</span>
                </a>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
    </span>
  )
}
