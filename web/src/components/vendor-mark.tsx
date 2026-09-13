import { icons, rules, type Icon } from "@/components/vendor-marks.generated"

// Vendor marks for the device inventory: a FortiGate should look like a FortiGate.
//
// Where a CC0 source (simple-icons) has the brand, that mark is drawn. Where it
// does not — most printer makers and most German telephony makers are not in it —
// the vendor gets a monogram instead of nothing: two letters from its name, on a
// colour derived from that same name, so Canon looks like Canon every time and
// never like Brother. A drawn-from-memory logo would be a worse answer than an
// honest initial, and an empty square is the worst of the three.

export type { Icon }

/** The mark for a vendor string, or null when no CC0 source has the brand. */
export function vendorIcon(vendor: string | undefined): Icon | null {
  if (!vendor) return null
  const v = vendor.toLowerCase()
  for (const [re, slug] of rules) if (re.test(v)) return icons[slug] ?? null
  return null
}

// A pure black or very dark mark disappears on the console's ground: those are
// drawn in the foreground colour instead of the brand colour.
function drawColour(hex: string) {
  const n = parseInt(hex.slice(1), 16)
  const lum = (0.2126 * ((n >> 16) & 255) + 0.7152 * ((n >> 8) & 255) + 0.0722 * (n & 255)) / 255
  return lum < 0.28 ? "currentColor" : hex
}

// Legal forms and filler words carry no recognition; they only push the letters
// that do out of a two-letter monogram.
const noise = /\b(inc|corp|corporation|co|company|ltd|limited|llc|plc|gmbh|mbh|ag|kg|kgaa|se|sa|s\.a|sas|srl|spa|bv|b\.v|nv|oy|ab|as|aps|pte|pty|technologies|technology|tech|electronics|electronic|electric|systems|system|solutions|solution|networks|network|international|industries|industrial|group|holding|holdings|digital|computer|computers|communications|communication|devices|device|products|europe|deutschland|germany|the|of|and|und)\b\.?/g

/** The vendor's name without its legal form, for a label and for the monogram. */
export function vendorLabel(vendor: string): string {
  const cleaned = vendor
    .toLowerCase()
    .replace(/[.,]/g, " ")
    .replace(noise, " ")
    .replace(/\s+/g, " ")
    .trim()
  return cleaned || vendor.toLowerCase()
}

/** Two letters that stand for the vendor: initials when there are two words, else the first two. */
function initials(vendor: string): string {
  const words = vendorLabel(vendor).split(" ").filter(Boolean)
  if (words.length === 0) return "??"
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase()
  return (words[0][0] + words[1][0]).toUpperCase()
}

/**
 * hue turns a name into one of the wheel's positions, deterministically: the same
 * vendor is the same colour on every screen and in every session, and two vendors
 * in one list are almost never the same.
 */
function hue(s: string): number {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return Math.abs(h) % 360
}

/**
 * VendorMonogram is the mark for a vendor no CC0 icon set carries. It is
 * deliberately not logo-shaped: a rounded tile with initials reads as "this is
 * what we call that vendor", not as a brand mark we are passing off as theirs.
 */
export function VendorMonogram({ vendor, className = "size-4" }: { vendor: string; className?: string }) {
  const h = hue(vendorLabel(vendor))
  const fill = `oklch(0.62 0.13 ${h})`
  const text = `oklch(0.16 0.04 ${h})`
  return (
    <svg viewBox="0 0 24 24" className={className} role="img" aria-label={vendor}>
      <title>{vendor}</title>
      <rect x="0.5" y="0.5" width="23" height="23" rx="5" fill={fill} />
      <text x="12" y="12.2" textAnchor="middle" dominantBaseline="central" fill={text}
        fontSize="11" fontWeight="700" fontFamily="inherit" letterSpacing="-0.5">
        {initials(vendor)}
      </text>
    </svg>
  )
}

/**
 * VendorMark draws the vendor's own mark where there is one and a monogram where
 * there is not, so every device in the inventory can be told apart by eye.
 * Renders nothing only when the vendor itself is unknown.
 */
export function VendorMark({ vendor, className = "size-4" }: { vendor?: string; className?: string }) {
  if (!vendor || !vendor.trim()) return null
  const i = vendorIcon(vendor)
  if (!i) return <VendorMonogram vendor={vendor} className={className} />
  return (
    <svg viewBox="0 0 24 24" className={className} role="img" aria-label={i.t}>
      <title>{i.t}</title>
      <path d={i.d} fill={drawColour(i.c)} />
    </svg>
  )
}
