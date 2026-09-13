// The EX0 mark: the zero as a low-poly faceted ring, the way NetBird facets its bird.
// Drawn as vector, so it stays crisp at 18 px in the sidebar and at 512 px on a slide,
// and it needs no asset pipeline. Sixteen triangles, lit from the upper left.

const C = 50 // centre
const OUTER = 50
const INNER = 27

const corner = (r: number, k: number): [number, number] => {
  const a = ((-90 + k * 45) * Math.PI) / 180
  return [C + r * Math.cos(a), C + r * Math.sin(a)]
}
const out = Array.from({ length: 8 }, (_, k) => corner(OUTER, k))
const inn = Array.from({ length: 8 }, (_, k) => corner(INNER, k))

// The console accent oklch(0.72 0.19 150) and four steps around it, brightest first.
const MINT = "#6EE7A0"
const EMERALD = "#3DD778"
const SIGNAL = "#22C55E"
const MOSS = "#17914A"
const PINE = "#0D5C30"

// Two facets per octagon segment, starting at the top and going clockwise.
const shades: [string, string][] = [
  [MINT, SIGNAL], // top → upper right
  [EMERALD, MOSS], // upper right → right
  [SIGNAL, PINE], // right → lower right
  [MOSS, SIGNAL], // lower right → bottom
  [SIGNAL, PINE], // bottom → lower left
  [EMERALD, MOSS], // lower left → left
  [MINT, SIGNAL], // left → upper left
  [EMERALD, MINT], // upper left → top
]

const poly = (pts: [number, number][]) => pts.map(([x, y]) => `${x.toFixed(2)},${y.toFixed(2)}`).join(" ")

/** The faceted zero on its own — the app icon. */
export function Mark({ className = "size-6", title }: { className?: string; title?: string }) {
  return (
    <svg viewBox="0 0 100 100" className={className} role={title ? "img" : "presentation"} aria-label={title} aria-hidden={title ? undefined : true}>
      {shades.map(([a, b], k) => {
        const n = (k + 1) % 8
        return (
          <g key={k}>
            <polygon points={poly([out[k], out[n], inn[k]])} fill={a} />
            <polygon points={poly([out[n], inn[n], inn[k]])} fill={b} />
          </g>
        )
      })}
    </svg>
  )
}

/** Mark plus wordmark, for the sidebar header and the login page. */
export function Logo({ className = "" }: { className?: string }) {
  return (
    <span className={"inline-flex items-center gap-2 " + className}>
      <Mark className="size-7 shrink-0" title="EX0" />
      <span className="text-lg font-semibold leading-none tracking-tight">
        EX<span className="text-primary">0</span>
      </span>
    </span>
  )
}
