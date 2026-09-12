import { Link, useLocation } from "react-router"
import { Activity, Box, Building2, Download, Settings2, ShieldAlert, FileClock, KeyRound, LayoutDashboard, LogOut, Search, ShieldCheck, Users, Webhook, Wrench } from "lucide-react"
import {
  Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarHeader,
  SidebarMenu, SidebarMenuBadge, SidebarMenuButton, SidebarMenuItem, SidebarRail,
} from "@/components/ui/sidebar"
import { Kbd } from "@/components/ui/kbd"
import { post, type Me } from "@/lib/api"

const watch = [
  { to: "/", label: "Übersicht", icon: LayoutDashboard },
  { to: "/tenants", label: "Kunden", icon: Building2, count: (m: Me) => m.Nav.Tenants },
  { to: "/events", label: "Ereignisse", icon: Activity, count: (m: Me) => m.Nav.Attention, bad: true },
  { to: "/findings", label: "Prävention", icon: ShieldAlert, count: (m: Me) => m.Nav.Findings },
  { to: "/maintenance", label: "Wartung", icon: Wrench },
]
const fleet = [
  { to: "/boxes", label: "Boxen", icon: Box, count: (m: Me) => m.Nav.Boxes, bad: (m: Me) => m.Nav.Unassigned > 0 },
  { to: "/updates", label: "Updates", icon: Download },
]
const system = [
  { to: "/keys", label: "Enrollment-Keys", icon: KeyRound },
  { to: "/webhooks", label: "Webhooks", icon: Webhook },
  { to: "/tokens", label: "API-Tokens", icon: ShieldCheck },
  { to: "/users", label: "Benutzer", icon: Users },
  { to: "/audit", label: "Audit-Log", icon: FileClock },
  { to: "/settings", label: "Einstellungen", icon: Settings2 },
]

function isActive(path: string, to: string) {
  if (to === "/") return path === "/"
  if (to === "/tenants") return path.startsWith("/tenants") || path.startsWith("/sites") || path.startsWith("/devices") || path.startsWith("/hosts")
  return path.startsWith(to)
}

export function AppSidebar({ me, onSearch }: { me: Me; onSearch: () => void }) {
  const { pathname } = useLocation()
  const logout = async () => { await post("/api/logout"); window.location.href = "/login" }
  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild>
              <Link to="/">
                <div className="flex aspect-square size-8 items-center justify-center rounded-md bg-sidebar-primary text-sidebar-primary-foreground text-[11px] font-bold">EX0</div>
                <div className="grid flex-1 text-left text-sm leading-tight"><span className="truncate font-semibold">EX0 Konsole</span><span className="truncate text-xs text-muted-foreground">VIICO GmbH</span></div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
          <SidebarMenuItem>
            <SidebarMenuButton onClick={onSearch} tooltip="Suche">
              <Search /><span>Suchen …</span><Kbd className="ml-auto">⌘K</Kbd>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Überwachung</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {watch.map((it) => {
                const c = it.count?.(me) ?? 0
                return (
                  <SidebarMenuItem key={it.to}>
                    <SidebarMenuButton asChild isActive={isActive(pathname, it.to)} tooltip={it.label}>
                      <Link to={it.to}><it.icon /><span>{it.label}</span></Link>
                    </SidebarMenuButton>
                    {c > 0 && <SidebarMenuBadge className={it.bad ? "text-destructive font-semibold" : ""}>{c}</SidebarMenuBadge>}
                  </SidebarMenuItem>
                )
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
        <SidebarGroup>
          <SidebarGroupLabel>Flotte</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {fleet.map((it) => {
                const c = it.count?.(me) ?? 0
                const bad = typeof it.bad === "function" ? it.bad(me) : false
                return (
                  <SidebarMenuItem key={it.to}>
                    <SidebarMenuButton asChild isActive={isActive(pathname, it.to)} tooltip={it.label}>
                      <Link to={it.to}><it.icon /><span>{it.label}</span></Link>
                    </SidebarMenuButton>
                    {c > 0 && <SidebarMenuBadge className={bad ? "text-destructive font-semibold" : ""}>{c}</SidebarMenuBadge>}
                  </SidebarMenuItem>
                )
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
        <SidebarGroup>
          <SidebarGroupLabel>Verwaltung</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {system.map((it) => {
                const c = 0
                const bad = false
                return (
                  <SidebarMenuItem key={it.to}>
                    <SidebarMenuButton asChild isActive={isActive(pathname, it.to)} tooltip={it.label}>
                      <Link to={it.to}><it.icon /><span>{it.label}</span></Link>
                    </SidebarMenuButton>
                    {c > 0 && <SidebarMenuBadge className={bad ? "text-destructive font-semibold" : ""}>{c}</SidebarMenuBadge>}
                  </SidebarMenuItem>
                )
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
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
