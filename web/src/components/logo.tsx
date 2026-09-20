import { useId } from "react"

// Die EX0-Marke: eine durchgestrichene Null, deren Ring an genau einer Stelle
// offen ist — dort, wo der Strich hinausgeht.
//
// Warum diese Form und nicht das facettierte Achteck, das hier stand:
//
//   * Das README sagt den Satz selbst: „The zero is the promise." Null offene
//     Ports beim Kunden, null Kundenzugangsdaten in der Mitte, null unsignierte
//     Updates. Also ist die Marke die Null und nichts sonst — kein Schild, kein
//     Auge, kein Schloss, die hat jeder in dieser Branche.
//   * `ex0` und `exo` sind zu leicht zu verwechseln; auch das steht im README.
//     Die durchgestrichene Null ist genau das Zeichen, das es dagegen gibt. Sie
//     kommt aus dem Terminal und liest sich nie als Buchstabe.
//   * Unten links ist der Ring geschlossen, und der Strich stößt nur an. Oben
//     rechts ist er offen, und der Strich tritt aus. Das ist die Invariante,
//     gezeichnet: Verbindungsaufbau nur Box → Server, nie zurück.
//
// Flache Kappen, und die Lücke wird nicht als Bogen gerechnet, sondern mit
// einer Maske aus dem vollen Ring geschnitten: Nur so laufen ihre Kanten
// parallel zum Strich und die Luft ist auf beiden Seiten gleich breit. Das
// Zeichen soll konstruiert aussehen, nicht gemalt.

const C = 50 // Mitte
const R = 33 // Mittellinie des Rings
const SW = 13 // Ringstärke
const SP = 12 // Strichstärke
const CLEAR = 7 // Luft zwischen Strich und Ring
const S0 = -31 // Anfang des Strichs, innerhalb des Rings
const S1 = 54 // Ende, außerhalb

const k = Math.SQRT1_2 // der Strich liegt auf 45°, wie der einer Terminal-Null
const A = [C + k * S0, C - k * S0] as const
const B = [C + k * S1, C - k * S1] as const
const CHANNEL = SP + 2 * CLEAR

/** Die Null allein — das App-Symbol und das Zeichen in der eingeklappten Leiste. */
export function Mark({ className = "size-6", title }: { className?: string; title?: string }) {
  // Eine eigene Id je Marke: Zwei Masken mit demselben Namen auf einer Seite,
  // und die zweite gewinnt — dann fehlt der einen die Lücke. Die Satzzeichen,
  // die React in seine Ids legt, fliegen raus: In `url(#…)` haben sie nichts
  // verloren, auch wenn die meisten Browser darüber hinwegsehen.
  const id = "m" + useId().replace(/[^a-zA-Z0-9_-]/g, "")
  return (
    <svg
      viewBox="-6 -6 112 112"
      className={className}
      role={title ? "img" : "presentation"}
      aria-label={title}
      aria-hidden={title ? undefined : true}
    >
      <defs>
        <mask id={id} maskUnits="userSpaceOnUse" x={-10} y={-10} width={120} height={120}>
          <rect x={-10} y={-10} width={120} height={120} fill="#fff" />
          <rect
            x={C}
            y={C - CHANNEL / 2}
            width={70}
            height={CHANNEL}
            fill="#000"
            transform={`rotate(-45 ${C} ${C})`}
          />
        </mask>
      </defs>
      <g fill="none" stroke="currentColor" strokeLinecap="butt">
        <circle cx={C} cy={C} r={R} strokeWidth={SW} mask={`url(#${id})`} />
        <path d={`M${A[0].toFixed(2)} ${A[1].toFixed(2)} L${B[0].toFixed(2)} ${B[1].toFixed(2)}`} strokeWidth={SP} />
      </g>
    </svg>
  )
}

/** Der Schriftzug: E, X und die Null als ein Wort — kein Abzeichen mit einem
 *  Namen daneben. Eingeklappt treten die Buchstaben zurück und die Null steht
 *  allein. */
export function Wordmark({ className = "" }: { className?: string }) {
  return (
    <span className={"flex items-center text-[20px] font-bold leading-none tracking-tight " + className}>
      <span className="group-data-[collapsible=icon]:hidden">EX</span>
      <Mark className="ml-[0.06em] size-[1.12em] shrink-0 text-primary" title="EX0" />
    </span>
  )
}
