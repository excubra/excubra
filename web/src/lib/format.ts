// Formatting helpers: German, local time zone, tabular.

const ZERO = "0001-01-01T00:00:00Z"

export function isZero(t?: string | null): boolean {
  return !t || t.startsWith("0001-01-01")
}

export function fmtTime(t?: string | null): string {
  if (isZero(t)) return "–"
  const d = new Date(t as string)
  return d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
}

export function fmtDateTime(t?: string | null): string {
  if (isZero(t)) return "–"
  const d = new Date(t as string)
  return d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit", year: "numeric" }) + " " + d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" })
}

export function fmtShort(t?: string | null): string {
  if (isZero(t)) return "–"
  const d = new Date(t as string)
  return d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" }) + " " + d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" })
}

export function humanDur(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000))
  if (s < 60) return `${s} s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m} min`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h} h ${String(m % 60).padStart(2, "0")} min`
  return `${Math.floor(h / 24)} Tage`
}

export function ago(t?: string | null, now: number = Date.now()): string {
  if (isZero(t)) return "–"
  const d = now - new Date(t as string).getTime()
  return d < 0 ? `in ${humanDur(-d)}` : `vor ${humanDur(d)}`
}

export function gb(bytes: number): string {
  return (bytes / 1e9).toFixed(1).replace(".", ",")
}

export function pct(v: number): string {
  return v.toFixed(1).replace(".", ",")
}

export function n(v: number): string {
  return new Intl.NumberFormat("de-DE").format(v)
}

export { ZERO }
