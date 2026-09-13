import { ChevronDown, ExternalLink } from "lucide-react"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { cn } from "@/lib/utils"
import type { WayIn } from "@/lib/api"

// Getting onto a device should not mean selecting an address, copying it, opening
// a second window and typing a scheme and a port in front of it. The browser
// opens http and https itself and hands ssh, rdp, vnc and smb to the client the
// operator already has installed.
//
// Which ways exist is decided on the server (internal/server/console/connect.go)
// from what the scan actually saw — a completed TLS handshake, an HTML title —
// and from any connector an operator configured. Deliberately not from a table of
// port numbers here: a FortiGate's web interface sits on 443 at one customer and
// on 10443 at the next, and a hardcoded list is wrong at exactly the customer who
// moved it.
//
// It works because the site's LAN is routed into the operator overlay: the
// address the box reports is reachable from the operator's own machine.

const standard: Record<string, number> = { https: 443, http: 80, ssh: 22, rdp: 3389, vnc: 5900, smb: 445, ftp: 21 }

const label: Record<string, string> = {
  https: "Weboberfläche (HTTPS)",
  http: "Weboberfläche (HTTP)",
  ssh: "SSH",
  rdp: "Remotedesktop",
  vnc: "VNC",
  smb: "Dateifreigabe",
  ftp: "FTP",
}

/** The address a client is handed. The port is left off when it is the usual one. */
export function hrefFor(w: WayIn, ip: string): string {
  const port = w.port === standard[w.kind] ? "" : `:${w.port}`
  return `${w.kind}://${ip}${port}`
}

/** How the menu names a way, with the port when it is not the usual one. */
export function labelFor(w: WayIn): string {
  const name = label[w.kind] ?? w.kind.toUpperCase()
  return w.port === standard[w.kind] ? name : `${name} · Port ${w.port}`
}

/**
 * ServicePort renders one scanned port. Where the console knows a way in on that
 * port, the port is the link; otherwise it is the plain "tcp/9100" it always was.
 */
export function ServicePort({ proto, port, ip, ways, gone }: { proto: string; port: number; ip: string; ways?: WayIn[] | null; gone?: boolean }) {
  const text = `${proto || "tcp"}/${port}`
  const w = gone ? undefined : (ways ?? []).find((x) => x.port === port)
  if (!w || !ip) return <span className="font-mono text-xs">{text}</span>
  return (
    <a href={hrefFor(w, ip)} target="_blank" rel="noreferrer" title={`${labelFor(w)} — ${w.note}`}
      className="font-mono text-xs underline decoration-dotted underline-offset-2 hover:text-primary hover:decoration-solid">
      {text}
    </a>
  )
}

/**
 * ConnectIP renders the address as the way in. One click follows the most likely
 * protocol; the chevron offers the rest. Without a usable way it is plain text,
 * because a link that goes nowhere is worse than none.
 */
export function ConnectIP({ ip, ways, className, sub }: { ip: string; ways?: WayIn[] | null; className?: string; sub?: string }) {
  const targets = ways ?? []
  if (!ip) return <span className={cn("text-muted-foreground", className)}>keine IPv4</span>
  if (targets.length === 0) {
    return <span className={cn("font-mono", className)}>{ip}{sub && <span className="block text-xs text-muted-foreground">{sub}</span>}</span>
  }
  const first = targets[0]
  return (
    <span className={cn("inline-flex items-start gap-1", className)}>
      <span className="min-w-0">
        <a href={hrefFor(first, ip)} target="_blank" rel="noreferrer" title={`${labelFor(first)} — ${first.note}`}
          onClick={(e) => e.stopPropagation()}
          className="font-mono underline decoration-dotted underline-offset-2 hover:text-primary hover:decoration-solid">
          {ip}{first.port !== standard[first.kind] ? <span className="text-muted-foreground">:{first.port}</span> : null}
        </a>
        {sub && <span className="block text-xs text-muted-foreground">{sub}</span>}
      </span>
      {targets.length > 1 && (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="size-5 shrink-0 text-muted-foreground" aria-label="Andere Verbindung" onClick={(e) => e.stopPropagation()}>
              <ChevronDown className="size-3" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" onClick={(e) => e.stopPropagation()}>
            <DropdownMenuLabel>Verbinden mit {ip}</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {targets.map((w) => (
              <DropdownMenuItem key={`${w.kind}:${w.port}`} asChild>
                <a href={hrefFor(w, ip)} target="_blank" rel="noreferrer" className="flex items-center gap-2">
                  <ExternalLink className="size-3.5" />
                  <span className="flex-1">{labelFor(w)}</span>
                  <span className="text-xs text-muted-foreground">{w.note}</span>
                </a>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
    </span>
  )
}
