import { useEffect, useState } from "react"
import { fingerprint } from "@/lib/seal"

// The box's seal key as a person compares it: 16 hex characters in groups of four.
export function SealFingerprint({ sealKey, className }: { sealKey: string; className?: string }) {
  const [fp, setFp] = useState("")
  useEffect(() => {
    let alive = true
    if (!sealKey) return
    fingerprint(sealKey).then((v) => { if (alive) setFp(v) })
    return () => { alive = false }
  }, [sealKey])
  if (!sealKey) return <span className="text-muted-foreground">noch nicht gemeldet (Agent zu alt)</span>
  return <span className={"font-mono " + (className ?? "")}>{fp || "…"}</span>
}
