import { useEffect, useState } from "react"

export function Clock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t) }, [])
  return <span className="font-mono text-sm tabular-nums text-muted-foreground">{now.toLocaleTimeString("de-DE")}</span>
}

// Ago re-renders every second so "vor 29 s" stays true.
export function Ago({ t }: { t?: string | null }) {
  const [, tick] = useState(0)
  useEffect(() => { const i = setInterval(() => tick((x) => x + 1), 1000); return () => clearInterval(i) }, [])
  if (!t || t.startsWith("0001-01-01")) return <>–</>
  const d = Date.now() - new Date(t).getTime()
  // Distance, not elapsed time: a patch deadline is the first thing in this
  // console that lies in the future, and "in 0 s" for "in zwölf Tagen" is the
  // kind of wrong that reads as urgent.
  const s = Math.floor(Math.abs(d) / 1000)
  let out: string
  if (s < 60) out = `${s} s`
  else if (s < 3600) out = `${Math.floor(s / 60)} min`
  else if (s < 172800) out = `${Math.floor(s / 3600)} h ${String(Math.floor(s / 60) % 60).padStart(2, "0")} min`
  else out = `${Math.floor(s / 86400)} Tagen` // dative: it is always read as "vor …" or "in …"
  return <>{d < 0 ? `in ${out}` : `vor ${out}`}</>
}
