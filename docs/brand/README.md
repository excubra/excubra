# Die Marke

Eine durchgestrichene Null. Der Ring ist geschlossen — bis auf eine Stelle oben
rechts, und dort geht der Strich hinaus.

Drei Gründe, und alle drei stehen schon im README des Projekts:

- **Die Null ist das Versprechen.** Null offene Ports beim Kunden, null
  Kundenzugangsdaten in der Mitte, null unsignierte Updates. Also ist die Marke
  die Null selbst — kein Schild, kein Auge, kein Schloss.
- **Sie liest sich nie als Buchstabe.** `ex0` und `exo` sind zu leicht zu
  verwechseln. Die durchgestrichene Null ist genau das Zeichen, das es dagegen
  gibt; sie kommt aus dem Terminal.
- **Die Richtung steckt drin.** Unten links ist der Ring zu und der Strich stößt
  nur an. Oben rechts ist er offen und der Strich tritt aus: Verbindungsaufbau
  nur Box → Server, nie zurück.

Flache Kappen, und die Lücke ist nicht als Bogen gerechnet, sondern mit einer
Maske aus dem vollen Ring geschnitten — nur so laufen ihre Kanten parallel zum
Strich und die Luft ist auf beiden Seiten gleich breit.

| Datei | Wofür |
| --- | --- |
| `mark.svg` | die Null in Grün `#22C55E` — Favicon, App-Symbol, Seitensymbol |
| `mark-mono.svg` | dieselbe Null in `currentColor` — einfarbig, erbt die Textfarbe |
| `wordmark.svg` | EX0 für helle Flächen |
| `wordmark-dark.svg` | EX0 für dunkle Flächen |

Im Code lebt die Marke als Bauteil in `web/src/components/logo.tsx`; die
Geometrie steht dort einmal und wird nicht kopiert. `internal/server/console/static/mark.svg`
ist dieselbe Zeichnung als Datei, weil das Favicon keine React-Komponente laden kann.

Grün ist der Akzent der Konsole und heißt „läuft". Rot ist für „dringend"
reserviert und kommt in der Marke nicht vor.
