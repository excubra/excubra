// Talks to the console's JSON API. Same-origin, session cookie, CSRF header on writes.
// Mutations post form-encoded bodies because the server handlers already parse forms
// and answer {ok, message} when asked for JSON.

let csrf = ""
export function setCSRF(token: string) { csrf = token }

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) { super(message); this.status = status }
}

async function handle<T>(res: Response): Promise<T> {
  if (res.status === 401) { window.location.href = "/login"; throw new ApiError(401, "Anmeldung abgelaufen") }
  const text = await res.text()
  let body: unknown = null
  try { body = text ? JSON.parse(text) : null } catch { body = { error: text } }
  if (!res.ok) {
    const msg = (body as { error?: string; message?: string } | null)?.error ?? (body as { message?: string } | null)?.message ?? `HTTP ${res.status}`
    throw new ApiError(res.status, msg)
  }
  return body as T
}

export async function get<T>(path: string, params?: Record<string, string | undefined>): Promise<T> {
  const url = new URL(path, window.location.origin)
  if (params) for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") url.searchParams.set(k, v)
  const res = await fetch(url.toString(), { headers: { Accept: "application/json" }, credentials: "same-origin" })
  return handle<T>(res)
}

export async function post<T = { ok: boolean; message: string }>(path: string, form?: Record<string, string | number | boolean | undefined>): Promise<T> {
  const body = new URLSearchParams()
  if (form) for (const [k, v] of Object.entries(form)) if (v !== undefined) body.set(k, String(v))
  const res = await fetch(path, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrf },
    credentials: "same-origin",
    body,
  })
  return handle<T>(res)
}

// ---- types mirrored from the Go side (field names as Go marshals them) ----

export interface Me { user: string; csrf: string; version: string; now: string; secure: boolean; Nav: { Tenants: number; Boxes: number; Unassigned: number; Attention: number; Findings: number } }

export interface BoxState { ID: string; Status: string; LastHeartbeat: string; SilentSince: string; AgentVersion: string }
export interface BoxRow {
  ID: string; SiteID: string; Name: string; HWID: string; AgentVersion: string; OS: string; Arch: string; CertSerial: string; CertNotAfter: string
  Channel: string; DiscoveryMode: string; DiscoverySubnets: string[] | null; NetbirdStatus: string; NetbirdIP: string; NetbirdOpStatus?: string; NetbirdOpIP?: string
  DiskTotalBytes: number; DiskFreeBytes: number; UptimeS: number; LastSeen: string; EnrolledAt: string; RevokedAt: string | null
  SealKey?: string
  State: BoxState; SiteName: string; TenantName: string; Assigned: boolean
}
export interface Tenant { ID: string; Name: string; CreatedAt: string }
export interface Site { ID: string; TenantID: string; Name: string; CreatedAt: string }
export interface HostState { Observed: string; Reported: string; Failures: number; Successes: number; Since: string; LastBoxTime?: string }
export interface HostRow {
  ID: string; TenantID: string; SiteID: string; BoxID: string; DeviceID: string; Name: string; Address: string; MAC: string; Vendor: string
  ParentID: string; IsUplink: boolean; Checks: string; CreatedAt: string; State: HostState; Suppressed: string; StateClass: string; StateLabel: string
}
export interface HourBucket { Label: string; Rounds: number; Failed: number; Pct: number; Class: string; Height: number }
export interface Availability { Rounds: number; Failed: number; Pct: number; Hours: HourBucket[] }
export interface HostCard extends HostRow { UplinkName: string; Avail: Availability }
export interface EventRow {
  event_id: string; type: string; severity: string; occurred_at: string; received_at: string; since?: string
  tenant_id: string; site_id?: string; box_id?: string; host_id?: string; device_id?: string; source: string
  host?: { id: string; name: string; address: string }; device?: { id: string; ip: string; mac: string; hostname: string; vendor: string }
  details?: Record<string, unknown>
  TenantName: string; SiteName: string; Class: string; Title: string; Info: string
}
export interface SiteCard {
  Site: Site; Tenant: Tenant; Box: BoxRow | null; HasBox: boolean; Online: boolean; Monitored: number; Up: number; Down: number; Devices: number
  Class: string; Last: EventRow | null; Hosts: HostRow[] | null
}
export interface ChartBucket { Label: string; At: string; OK: number; Failed: number }
export interface ChartData { Range: string; AxisLabels: string[]; Buckets: ChartBucket[]; Rounds: number; Failed: number; Pct: number; Hosts: number }
export interface Overview {
  Up: number; Down: number; Unknown: number; Maint: number; Silent: number; Total: number; Boxes: number; Recent: EventRow[] | null
  Cards: SiteCard[] | null; Unassigned: BoxRow[] | null; Devices: number; SitesOnline: number; SitesWithBox: number; SitesTotal: number; Events24h: number
  Chart: ChartData
  attention: Attention[] | null
}
export interface AckView { actor: string; at: string; note: string }
export interface Attention { kind: string; since: string; tenant: string; tenantId: string; site: string; siteId: string; name: string; address: string; id: string; href: string; detail: string; ack?: AckView }
export interface TenantRow extends Tenant { sites: number; boxes: number; boxesOnline: number; hosts: number; down: number; devices: number; attention: number }
export interface TenantDetail { tenant: Tenant; sites: SiteCard[] | null; events: EventRow[] | null }
export interface DeviceCard {
  ID: string; TenantID: string; SiteID: string; MAC: string; IP: string; Vendor: string; Hostname: string; FirstSeen: string; LastSeen: string; GoneAt: string | null; Ignored: boolean
  Kind: string; KindLabel: string; Name: string; Monitored: boolean; HostID: string; IsUplink: boolean; StateClass: string; StateLabel: string; IsBox: boolean; Text: string
}
export interface KindCount { Key: string; Label: string; N: number }
export interface SiteData {
  Site: Site; Tenant: Tenant; Boxes: BoxRow[] | null; Box: BoxRow | null; Online: boolean
  Devices: DeviceCard[] | null; Kinds: KindCount[] | null; Ignored: number
  Hosts: HostCard[] | null; Up: number; Down: number; Unknown: number; Maint: number; Monitored: number
  Events: EventRow[] | null; Red: number; Tab: string; Chart: ChartData
  Sites: Site[] | null; TenantNames: Record<string, string>; Fingerprint: string; Netbird: { ManagementURL: string; ClaimedAt: string | null } | null; Subnets: string
}
export interface DeviceDetail { device: DeviceCard; tenant: Tenant; site: Site; host: HostCard | null; events: EventRow[] | null; logsNote: string }
export interface BoxesData { Unassigned: BoxRow[] | null; Assigned: BoxRow[] | null }
export interface BoxTask { ID: string; BoxID: string; Kind: string; IssuedAt: string; IssuedBy: string; ExpiresAt: string; DoneAt: string | null; OK: boolean | null; Detail: string }
export interface BoxNote { ID: number; BoxID: string; At: string; Text: string }
export interface BoxData { Row: BoxRow; Sites: Site[] | null; TenantNames: Record<string, string>; Hosts: HostRow[] | null; Netbird: { ManagementURL: string; ClaimedAt: string | null } | null; Fingerprint: string; Subnets: string; Tasks: BoxTask[] | null; Notes: BoxNote[] | null }
export interface Release { Version: string; OS: string; Arch: string; URL: string; SHA256: string; Signature: string; MinAgentVersion: string; CreatedAt: string }
export interface UpdateRow extends BoxRow { Target: string; Behind: boolean; LastNote: BoxNote | null; Pending: BoxTask[] | null }
export interface CatalogStatus { url: string; lastCheck: string; lastError: string; lastAdded: string[] }
export interface ServerUpdateStatus { enabled: boolean; running: string; arch: string; channel: string; target: string; available: string; lastCheck: string; lastError: string; rolledBack: string }
export interface UpdatesData { Boxes: UpdateRow[] | null; Releases: Release[] | null; Channels: Record<string, string>; Versions: string[] | null; Behind: number; Current: number; NoTarget: number; Catalog: CatalogStatus | null; Server: ServerUpdateStatus | null }
export interface HostData {
  View: HostRow; Row: HostRow; Box: BoxRow; Site: Site; Tenant: Tenant; Siblings: HostRow[] | null
  Windows: MaintenanceWindow[] | null; Form: { ICMP: boolean; TCPPort: number; HTTPURL: string }; Rounds: number; Failed: number; Availability: number
  Events: EventRow[] | null; Hours: HourBucket[] | null; Tab: string
}
export interface MaintenanceWindow { ID: string; Scope: string; TargetID: string; Until: string; Reason: string; SetBy: string; StartedAt?: string }
export interface KeyRow { id: string; note: string; createdAt: string; expiresAt: string; usedAt: string | null; usedBy: string; revokedAt: string | null }
export interface TokenRow { id: string; name: string; tenants: string[]; createdAt: string; lastUsed: string | null; revokedAt: string | null }
export interface WebhookRow { id: string; name: string; url: string; enabled: boolean; createdAt: string }
export interface UserRow { id: string; name: string; totp: boolean; disabled: boolean; locked: boolean; lockedUntil: string | null; failedLogins: number; createdAt: string }
export interface AuditRow { ID: number; At: string; Actor: string; Action: string; Target: string; Summary: string }
export interface SearchHit { kind: string; id: string; title: string; sub: string; href: string; tenant: string }
export interface ConnectorView {
  id: string; deviceId: string; kind: string; kindLabel: string; url: string; sealedBy: string; sealedAt: string; intervalS: number
  tlsFingerprint: string; seenFingerprint: string; disabled: boolean; lastOk: boolean | null; lastError: string; lastAt: string | null
  facts: Record<string, unknown>; factsAt: string | null; metrics: Record<string, number>; class: "ok" | "failed" | "paused" | "pending"
}
export interface KindMode { id: string; label: string; hint: string; fields: string[] }
export interface KindOption { kind: string; label: string; fields: string[]; modes?: KindMode[] }
export interface DeviceConnectors { box: BoxRow | null; sealKey: string; fingerprint: string; online: boolean; kinds: KindOption[]; connectors: ConnectorView[] }
export interface FindingView {
  id: string; tenantId: string; tenant: string; siteId: string; site: string; deviceId: string; device: string; connectorId: string
  rule: string; key: string; severity: "high" | "medium" | "low"; title: string; detail: string; evidence: Record<string, unknown>
  firstSeen: string; lastSeen: string; resolvedAt: string | null; ack?: AckView
}
export interface FindingsData { open: FindingView[]; resolved?: FindingView[]; counts: Record<string, number> }
export interface SamplePoint { at: string; value: number }
export interface RemoteAccessRow { SiteID: string; TenantID: string; BoxID: string; CIDR: string; Enabled: boolean; State: "key" | "joining" | "wiring" | "active" | "off" | "error"; Detail: string; PeerID: string; PeerIP: string; NetworkID: string; ResourceID: string; RouterID: string; RequestedBy: string; CreatedAt: string; UpdatedAt: string }
export interface SiteRemote { configured: boolean; access: RemoteAccessRow | null; suggested: string; boxOperator: string; boxOpIp: string; labels: Record<string, string> }
export interface NetbirdSettings { url: string; hasToken: boolean; techGroup: string; lanGroup: string; boxGroup: string }
