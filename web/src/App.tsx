import { useEffect, useState } from "react"
import { Routes, Route, Navigate, useLocation } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { Toaster } from "@/components/ui/sonner"
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar"
import { Separator } from "@/components/ui/separator"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Spinner } from "@/components/ui/spinner"
import { AppSidebar } from "@/components/app-sidebar"
import { CommandMenu } from "@/components/command-menu"
import { Clock } from "@/components/clock"
import { get, setCSRF, type Me } from "@/lib/api"
import OverviewPage from "@/pages/overview"
import TenantsPage from "@/pages/tenants"
import SitesPage from "@/pages/sites"
import TenantPage from "@/pages/tenant"
import SitePage from "@/pages/site"
import DevicePage from "@/pages/device"
import HostPage from "@/pages/host"
import EventsPage from "@/pages/events"
import BoxesPage from "@/pages/boxes"
import BoxPage from "@/pages/box"
import UpdatesPage from "@/pages/updates"
import FindingsPage from "@/pages/findings"
import SettingsPage from "@/pages/settings"
import MaintenancePage from "@/pages/maintenance"
import KeysPage from "@/pages/keys"
import WebhooksPage from "@/pages/webhooks"
import TokensPage from "@/pages/tokens"
import UsersPage from "@/pages/users"
import AuditPage from "@/pages/audit"

export default function App() {
  const me = useQuery({ queryKey: ["me"], queryFn: () => get<Me>("/api/me"), refetchInterval: 30_000 })
  const [open, setOpen] = useState(false)
  const location = useLocation()

  useEffect(() => { if (me.data) setCSRF(me.data.csrf) }, [me.data])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen((o) => !o) }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])
  useEffect(() => { document.getElementById("main")?.scrollTo(0, 0) }, [location.pathname])

  if (me.isLoading) {
    return <div className="flex h-svh items-center justify-center text-muted-foreground"><Spinner /> <span className="ml-2">Konsole lädt …</span></div>
  }
  if (me.isError || !me.data) {
    return <div className="flex h-svh items-center justify-center text-muted-foreground">Nicht angemeldet. <a className="ml-1 underline" href="/login">Zur Anmeldung</a></div>
  }

  return (
    <TooltipProvider>
    <SidebarProvider>
      <AppSidebar me={me.data} onSearch={() => setOpen(true)} />
      <SidebarInset className="@container/main h-svh overflow-hidden">
        <header className="flex h-12 shrink-0 items-center gap-2 border-b px-3 sm:px-4">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4 sm:mr-2" />
          <div id="crumbs" className="min-w-0 flex-1 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden" />
          <div className="hidden sm:block"><Clock /></div>
        </header>
        <main id="main" className="flex-1 overflow-y-auto">
          <div className="flex flex-col gap-6 p-4 md:p-6">
            <Routes>
              <Route path="/" element={<OverviewPage />} />
              <Route path="/tenants" element={<TenantsPage />} />
              <Route path="/tenants/:id" element={<TenantPage />} />
              <Route path="/sites" element={<SitesPage />} />
              <Route path="/sites/:id" element={<SitePage />} />
              <Route path="/devices/:id" element={<DevicePage />} />
              <Route path="/hosts/:id" element={<HostPage />} />
              <Route path="/events" element={<EventsPage />} />
              <Route path="/boxes" element={<BoxesPage />} />
              <Route path="/boxes/:id" element={<BoxPage />} />
              <Route path="/updates" element={<UpdatesPage />} />
              <Route path="/findings" element={<FindingsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/maintenance" element={<MaintenancePage />} />
              <Route path="/keys" element={<KeysPage />} />
              <Route path="/webhooks" element={<WebhooksPage />} />
              <Route path="/tokens" element={<TokensPage />} />
              <Route path="/users" element={<UsersPage />} />
              <Route path="/audit" element={<AuditPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </main>
      </SidebarInset>
      <CommandMenu open={open} onOpenChange={setOpen} />
      <Toaster position="bottom-right" richColors />
    </SidebarProvider>
    </TooltipProvider>
  )
}
