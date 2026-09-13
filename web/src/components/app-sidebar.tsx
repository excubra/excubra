import { Link, useLocation } from "react-router"
import { Activity, Box, Building2, Download, Settings2, ShieldAlert, FileClock, KeyRound, LayoutDashboard, LogOut, MapPin, Search, ShieldCheck, Users, Webhook, Wrench } from "lucide-react"
import {
  Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarHeader,
  SidebarMenu, SidebarMenuBadge, SidebarMenuButton, SidebarMenuItem, SidebarRail, useSidebar,
} from "@/components/ui/sidebar"
import { Kbd } from "@/components/ui/kbd"
import { Wordmark } from "@/components/logo"
import { post, type Me } from "@/lib/api"

type Item = { to: string; label: string; icon: typeof Box; count?: (m: Me) => number; bad?: boolean | ((m: Me) => boolean) }

// Daily work first, the fleet second, the things you set up once at the bottom.
const operate: Item[] = [
  { to: "/", label: "Übersicht", icon: LayoutDashboard },
  { to: "/sites", label: "Standorte", icon: MapPin, count: (m) => m.Nav.Sites },
  { to: "/tenants", label: "Kunden", icon: Building2, count: (m) => m.Nav.Tenants },
  { to: "/events", label: "Ereignisse", icon: Activity, count: (m) => m.Nav.Attention, bad: true },
  { to: "/findings", label: "Prävention", icon: ShieldAlert, count: (m) => m.Nav.Findings },
]
const fleet: Item[] = [
  { to: "/boxes", label: "Boxen", icon: Box, count: (m) => m.Nav.Boxes, bad: (m) => m.Nav.Unassigned > 0 },
  { to: "/updates", label: "Updates", icon: Download },
  { to: "/maintenance", label: "Wartung", icon: Wrench },
]
const system: Item[] = [
  { to: "/keys", label: "Enrollment-Keys", icon: KeyRound },
  { to: "/webhooks", label: "Webhooks", icon: Webhook },
  { to: "/tokens", label: "API-Tokens", icon: ShieldCheck },
  { to: "/users", label: "Benutzer", icon: Users },
  { to: "/audit", label: "Audit-Log", icon: FileClock },
  { to: "/settings", label: "Einstellungen", icon: Settings2 },
]

// What this operator pinned, above everything else. With fifty customers the
// groups below stop being a shortcut; the three somebody works with today belong
// at the top, and which three that is changes by the day and by the person.
function Pinned({ me, onGo }: { me: Me; onGo: () => void }) {
  const { pathname } = useLocation()
  const pins = me.pins ?? []
  if (pins.length === 0) return null
  return (
    <SidebarGroup>
      <SidebarGroupLabel>Angeheftet</SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          {pins.map((p) => {
            const to = p.kind === "site" ? `/sites/${p.id}` : `/tenants/${p.id}`
            return (
              <SidebarMenuItem key={`${p.kind}:${p.id}`}>
                <SidebarMenuButton asChild isActive={pathname === to} tooltip={p.sub ? `${p.name} · ${p.sub}` : p.name}>
                  <Link to={to} onClick={onGo}>
                    {p.kind === "site" ? <MapPin /> : <Building2 />}
                    <span className="truncate">{p.name}</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            )
          })}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}

function isActive(path: string, to: string) {
  if (to === "/") return path === "/"
  // a device or a host is reached through its site, so they light up "Standorte"
  if (to === "/sites") return path.startsWith("/sites") || path.startsWith("/devices") || path.startsWith("/hosts")
  return path.startsWith(to)
}

function Nav({ items, label, me, className, onGo }: { items: Item[]; label: string; me: Me; className?: string; onGo: () => void }) {
  const { pathname } = useLocation()
  return (
    <SidebarGroup className={className}>
      <SidebarGroupLabel>{label}</SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((it) => {
            const c = it.count?.(me) ?? 0
            const bad = typeof it.bad === "function" ? it.bad(me) : !!it.bad
            return (
              <SidebarMenuItem key={it.to}>
                <SidebarMenuButton asChild isActive={isActive(pathname, it.to)} tooltip={it.label}>
                  <Link to={it.to} onClick={onGo}><it.icon /><span>{it.label}</span></Link>
                </SidebarMenuButton>
                {c > 0 && <SidebarMenuBadge className={bad ? "font-semibold text-destructive" : ""}>{c}</SidebarMenuBadge>}
              </SidebarMenuItem>
            )
          })}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}

export function AppSidebar({ me, onSearch }: { me: Me; onSearch: () => void }) {
  const { isMobile, setOpenMobile } = useSidebar()
  const logout = async () => { await post("/api/logout"); window.location.href = "/login" }
  // on a phone the sidebar is a sheet: close it once the user is on their way
  const onGo = () => { if (isMobile) setOpenMobile(false) }
  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild>
              <Link to="/" onClick={onGo}>
                <Wordmark />
                <div className="grid flex-1 text-left text-xs leading-tight text-muted-foreground"><span className="truncate">Konsole</span><span className="truncate">VIICO GmbH</span></div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
          <SidebarMenuItem>
            <SidebarMenuButton onClick={() => { onGo(); onSearch() }} tooltip="Suche">
              <Search /><span>Suchen …</span><Kbd className="ml-auto">⌘K</Kbd>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <Pinned me={me} onGo={onGo} />
        <Nav items={operate} label="Betrieb" me={me} onGo={onGo} />
        <Nav items={fleet} label="Flotte" me={me} onGo={onGo} />
        <Nav items={system} label="System" me={me} onGo={onGo} className="mt-auto" />
      </SidebarContent>
      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" onClick={logout} tooltip="Abmelden">
              <div className="flex aspect-square size-8 items-center justify-center rounded-md bg-muted text-sm font-semibold uppercase">{me.user.slice(0, 1)}</div>
              <div className="grid flex-1 text-left text-sm leading-tight"><span className="truncate font-medium">{me.user}</span><span className="truncate font-mono text-xs text-muted-foreground">{me.version}</span></div>
              <LogOut className="ml-auto size-4 text-muted-foreground" />
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  )
}
