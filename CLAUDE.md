# excubra — EX0 (Excubra Zero)

Open-Source-Überwachung und Angriffserkennung für kleine Infrastrukturen. Marke **EX0**,
Repo/Binary/CLI heißen bewusst **`excubra`** (Homoglyphen-Gefahr `ex0`/`exo`).
Owner: Jeremia, VIICO GmbH. Lizenz Apache 2.0. Code und Kommentare Englisch,
Nutzer-Doku Deutsch + Englisch, Commit-Messages Englisch.

## Quelle der Wahrheit ist salt.md, nicht diese Datei

Vision, Scope, Vertrag und Entscheidungen stehen in salt.md (Workspace *Entwicklung* →
Systeme → EX0). Bei Widerspruch gewinnen die Seiten. Zu Sitzungsbeginn in dieser
Reihenfolge lesen (`get_page`):

1. **EX0** Hauptseite `37bc94317b579adce6dba6730711e9fc` — Vision, Sicherheits- und
   Betriebs-Invarianten vom 30.08.2026 (gelten alle). Der dortige Abschnitt
   „MVP (Phase 1)" und der dortige Initial-Prompt sind **Phase 2** und werden jetzt NICHT gebaut.
2. **Konzept & Architektur — Box und Phase 1 „EX0 dünn"** `a0e0248125ff9107adb4d70468bec4e4`
   — der Scope und die Definition of Done.
3. **Schnittstelle EX0 → CRM (Vertrag v1)** `c43f62383d7b5e321d3f4fbee4ab104b` — wortgetreu umsetzen.
4. **Entscheidungen & verworfene Wege** `0dc15d59aaadb0b2e441087be238ce71` — nichts
   Verworfenes wieder vorschlagen; neue Entscheidungen dort oben anhängen, mit Begründung.
5. **Initial-Prompt Claude Code — Phase 1** `8b08de82b001bc3e2034802e56f66a12`.

Plattform-Seite **NetBird** `bcdf1be4d3c66296b3885c92e806d8e3` (Fernzugriff, Overlay für die Konsole).

Technische Doku lebt im Repo: `docs/adr/` (verbindliche Architekturentscheidungen),
`docs/de/`, `docs/en/`. In salt stehen Status, Entscheidungen mit Begründung und offene
Vorgänge — nichts doppelt pflegen.

## Phase 1 „EX0 dünn" in einem Satz

Eine Box beim Kunden meldet jede Minute „ich lebe", prüft, ob die Systeme im LAN
erreichbar sind, kennt jedes Gerät im Netz, und der Server macht daraus
Zustandsübergänge, die per Webhook an ein CRM gehen. Keine Logs, keine Regeln, keine
Reports — das ist Phase 2 und darf durch das Design nur nicht verbaut werden.

## Invarianten (Kurzfassung — nie verletzen, Details in salt und docs/adr)

- Verbindungsaufbau nur Box → Server. Der Server kann beim Kunden nichts auslösen; er
  wählt nur aus einer festen Liste von Check-Arten und gibt Subnetze an.
- Ingest (mTLS, 443) ist der einzige öffentliche Endpunkt. Konsole nur am Overlay-Listener;
  die Status-API am Overlay und am eigenen Netz (ADR-0022), dort melden auch Quellen
  (ADR-0023). Kein gemeinsamer Handler, keine Umleitung.
- Mandant wird aus dem Client-Zertifikat abgeleitet, nie aus dem Payload.
  Enrollment-Keys einmalig; Zuordnung nur serverseitig — in der Konsole oder über
  die drei Einrichtungs-Werkzeuge des MCP-Servers (`ex0_create_tenant`,
  `ex0_create_site`, `ex0_new_box`), die dasselbe tun wie die Konsole, unter dem
  Actor der Sitzung. Nie von der Box aus.
- Discovery-Modi: `passive`, `sweep`. Der Dienst-Scan (ADR-0018, E20) ist je Standort
  geschaltet, gedrosselt, liest nur; nie Exploits, nie Zugangsdaten. Die Live-Erkennung
  (ADR-0018 §7) öffnet Köder-Ports, antwortet nichts und sendet nichts. Der DNS-Sensor
  (ADR-0020) ist je Standort aus, bis der Router auf die Box zeigt; er loggt keine Anfragen.
- Agent unprivilegiert (CAP_NET_RAW, CAP_NET_BIND_SERVICE), darf nie schaden: Ringpuffer Drop-Oldest, blockiert
  nie eine Anwendung, keine lokale Config-Datei (nur Key/Zertifikat + State-Verzeichnis).
- Updates nur signiert (Public Key einkompiliert); der Server kann nicht signieren.
  Atomarer Tausch, Health-Check, Rollback.
- Null externe Dienste auf dem Server: SQLite eingebettet (WAL), Dateien als Puffer.
- Ein Binary, zwei Rollen (`excubra agent`, `excubra server`) aus demselben Commit;
  Kompatibilitätsfenster zwei Minor-Versionen.
- Crash-only, at-least-once + Dedupe über `event_id`. Jedes Ereignis trägt Box-Zeit UND
  Server-Zeit; Korrelation über Server-Zeit.
- Ereignisse NUR bei Zustandsübergängen (3 verpasst → down, 2 Erfolge → up, Box-Silence
  friert Hosts ein, Uplink unterdrückt Kinder, Wartungsfenster).

## Bauen und testen

- Go laut `go.mod`, `CGO_ENABLED=0`, Linux amd64 + arm64. `make build`, `make test`,
  `make lint`, `make integration`. Lokal entwickeln auf macOS geht für alles außer
  Raw-Sockets (ARP/ICMP) — die haben Linux-Build-Tags und Fakes für Tests.
- Abhängigkeiten minimal: Stdlib zuerst. Jede neue Bibliothek braucht einen Satz in
  `docs/adr/0008-dependencies.md`, sonst kommt sie nicht rein.
- Kleine, lauffähige Schritte, jeder Schritt ein Commit. Zustandsmaschine mit
  Tabellentests für JEDEN Übergang. Reports und Ereignisse mit Golden-Files
  (`fixtures/`).

<!-- salt-entwicklung:start -->
## Arbeit in salt.md dokumentieren

Workspace **Entwicklung** (`70bbc4e36728b79862e92aa14979f037`), Stand 2026-09-05.
Neu holen mit `/salt-entwicklung`, wenn sich die Regeln geändert haben.
MCP-Endpunkt: `https://salt.viico.de/mcp`.

### Melde deine Arbeit an

Bevor du länger als einen Moment an einer Seite oder einem Vorgang arbeitest:

    working_on(page_id: "<id>", agent: "claude", label: "Claude Code",
               note: "was du tust, in wenigen Worten")

Am Ende dasselbe mit `done: true`. Die Notiz ist der wertvolle Teil — „räumt den
Datei-Index auf" beantwortet die Frage, die ein Mensch hat, „arbeitet" nicht.

Dazwischen musst du nichts tun: Jeder weitere Aufruf auf derselben Seite gilt
als Lebenszeichen, und die Anmeldung läuft nicht ab, während du woanders sitzt.

**Den Status trotzdem setzen.** Die Anmeldung sagt „ich bin gerade dran", der
Status sagt „so weit ist es". Auf *In Arbeit*, BEVOR du anfängst.

**Notizen unterwegs:** `note(page_id, text)` für das, was ein Write-up verliert — der
verworfene Ansatz, die Überraschung, warum nicht der naheliegende Weg. Eine Zeile,
sofort, nicht hinterher. Notizen sind unveränderlich.

**Entscheidungen** mit Begründung und verworfenen Optionen gehören auf die Seite
„Entscheidungen & verworfene Wege" (`0dc15d59aaadb0b2e441087be238ce71`), neue oben.

### Die Datenbanken

| Datenbank | Id | Wofür |
| --- | --- | --- |
| Systeme | `85f32056708b3b4d4f769aadfd8f5751` | „Was gibt es?" — eine Zeile je System, lebt für immer |
| Vorgänge | `50bc601cbae16834bbc3fcbe4d45c542` | „Was ist zu tun?" — eine Zeile je Aufgabe, immer mit System verknüpft |

Das System **EX0** ist die Zeile `37bc94317b579adce6dba6730711e9fc`. Neue Vorgänge:
`create_page(parent_id: "50bc601cbae16834bbc3fcbe4d45c542", properties: {"system": ["37bc94317b579adce6dba6730711e9fc"], ...})`
— die Relation ist IMMER eine Liste.

**Vorgänge** — Eigenschaften und Options-Ids (Werte werden per Id geschrieben, nie per Label):

- `status`: `eingang` · `als-naechstes` · `in-arbeit` · `wartet-auf-andere` · `erledigt` · `verworfen`
- `system`: Relation → Systeme (Liste!)
- `art`: `feature` · `fehler` · `update--sicherheit` · `wartung` · `recherche`
- `prio`: `dringend` · `normal` · `irgendwann`
- `aufwand`: `s--unter-1-tag` · `m--wenige-tage` · `l--wochen`
- `meilenstein`: Text (Phase 1 heißt „EX0 dünn (Phase 1)", Phase 2 „EX0 Phase 2")
- `faellig`: Datum (YYYY-MM-DD)

**Systeme** — Eigenschaften: `status` (`idee` · `in-entwicklung` · `in-betrieb` ·
`nur-wartung` · `abgeloest`), `art` (`app` · `website` · `integration--mcp` ·
`skript--werkzeug` · `infrastruktur`), `fuer` (`viico-intern` · `produkt--verkauf` ·
`kundenprojekt`), `kritisch` (`kritisch--sofort` · `wichtig--am-selben-tag` ·
`unkritisch`), `version`, `laeuft` („Läuft auf"), `repo`, `check` („Nächster Check", Datum).
`vorgaenge`/`offen`/`erledigt` sind abgeleitet — nie schreiben.

Vorgänge Phase 1 (Meilenstein „EX0 dünn (Phase 1)"):

| Vorgang | Id |
| --- | --- |
| ADRs + Repo-Skelett mit CI | `42e1b6ae5ce88d824854695069a17177` |
| Agent — Enrollment, Heartbeat, Host-Checks, Discovery, Config-Pull | `5b26ed24cbfc548b681acce5bed26747` |
| Server — Ingest mTLS, Zustandsmaschine, Webhook, Status-API | `1d67cbe763808e2edebd92c1735c53b6` |
| Konsole | `05d6b23271590c4588696b4c8b400818` |
| Box-Image | `621bc6c6eb0065b21decf44bb8559f4b` |
| Erste Box im VIICO-Büro, 7 Tage stabil | `bd64e2f33184a849f2bad54a4997f5f3` |
| Security-Audit (Fable 5.1, getaggter Stand) | `017339447c5a0c2302873434f2757097` |
| Phase 2: Erkennung | `490a8f0a742c6c4a3cc239d6eef00ead` |
| Erste Kundenbox beim Pilotkunden (Container muster-box auf dem Proxmox) | `7a730e2d28eb1101f9b2ccc3d7fb2dac` |
| Konsole: Neuaufbau 2026 (Vollbild, Standort-Seite, HTTPS, 2-Schritt-Login) | `394362a764f565df0ac8bf6f380295e5` |
| Konsole: Aktionen — Aufgaben an Boxen, Update-Verwaltung, Quittieren, Box-Meldungen | `fe2be95e18e19c52a1d7710a46694fe7` |

Vollausbau (Meilenstein „EX0 Vollausbau“, Konzept `2205aceb016e9cd8fa466b9178cf5358`, Entscheidung E15 auf der Entscheidungen-Seite; E16 wartet auf Jeremia):

| Vorgang | Id |
| --- | --- |
| V1 Konnektoren lesen: FortiGate und Starface über die Box | `2257581b987938d1d7278e23d17cd204` |
| V2 Operator-Signatur und typisierte Aufträge mit Freigabe | `8d452d2a9a78824a22ce241a8c275c05` |
| V3 Konfigurationsverwaltung: Vorlagen, Soll/Ist, Drift, Rollout | `46c7d18d89e2dda12609015f68e95adb` |
| V4 Geräte-Updates: Firmware im Wartungsfenster | `cd9d0aa1c99942a7c63c6f46df915a36` |
| V5 Logs je Gerät: Syslog auf der Box | `ec112b04db852350e880c00d4d7eaad5` |
| V6 Prävention: Regeln, Findings, KI-Triage | `9e2fd416e808b9cb70941e54ff8f6e9e` |
| V7 Client-Agent für Windows/macOS/Linux | `8acfaa93416f7658c992857b3e5173b9` |
| V8 Weitere Konnektoren: Proxmox, TrueNAS, UniFi, SNMP | `0daaa5c4a5d3fbfa62bebe0e88609845` |

### Die Regeln des Workspace (Wortlaut, Stand 2026-09-05)

Hier liegt die eigene Software- und Produktentwicklung — nicht die Kundenarbeit. Es gibt genau zwei Datenbanken, und sie beantworten zwei verschiedene Fragen.

#### Melde dich an, bevor du anfängst

**Wenn du als Agent länger als einen Moment an einer Seite oder einem Vorgang arbeitest, ruf zuerst `working_on(page_id, agent, note)` auf** — und am Ende noch einmal mit `done: true`. Die Notiz ist der wertvolle Teil: „räumt den Datei-Index auf" beantwortet die Frage, die ein Mensch tatsächlich hat, „arbeitet" nicht.

Der Grund ist nicht Buchhaltung. Wer zuschaut, sieht sonst eine Karte, die sich von selbst bewegt, und weiß weder wer noch warum. Zwischendurch musst du nichts tun: Jeder weitere Aufruf auf derselben Seite gilt als Lebenszeichen, und die Anmeldung läuft nicht ab, während du an etwas anderem sitzt.

Den Status trotzdem setzen — die Anmeldung ersetzt ihn nicht. Sie sagt „ich bin gerade dran", der Status sagt „so weit ist es".

#### Systeme — „was gibt es?"

Eine Zeile pro System, das existiert: App, Website, Integration, Skript, Infrastruktur. **Eine Zeile lebt für immer**, auch wenn nichts mehr daran gebaut wird — sie wechselt nur den Status: Idee → In Entwicklung → In Betrieb → Nur Wartung → Abgelöst. Es gibt kein „fertig", das etwas verschwinden lässt.

An der Zeile hängt alles Dauerhafte als Unterseite: Konzept, Architektur, Changelog, Betriebsanleitung, Zugangswege (nur Verweise — Zugangsdaten gehören in den Passwortmanager).

**Jedes System trägt sein echtes Logo.** Als Seitensymbol lässt sich ein Bild hochladen, genau wie beim Workspace-Bild; ein Icon aus der Auswahl ist die Notlösung, wenn es kein Logo gibt. Der Grund ist Wiedererkennung: In Auswahllisten, auf Karten und in der Seitenleiste steht das Symbol neben dem Namen, und ein echtes Logo findet man dort mit dem Auge statt mit dem Text.

**Bei eigenen Repositories:** Technische Doku bleibt im Repo. Hier steht, was man ohne Repo wissen will — Status, wo es läuft, welche Version, Entscheidungen, offene Vorgänge. Nichts doppelt pflegen.

#### Vorgänge — „was ist zu tun?"

Eine Zeile pro Aufgabe, **immer mit einem System verknüpft**. Art unterscheidet Feature, Fehler, Update/Sicherheit, Wartung, Recherche — dadurch bleibt Betriebsarbeit an einem laufenden System sichtbar, ohne das System selbst wieder „in Entwicklung" zu setzen.

Der Status ist der Arbeitsfluss: Eingang → Als Nächstes → In Arbeit → Wartet auf andere → Erledigt (oder Verworfen, mit einem Satz Begründung). Erledigtes bleibt stehen; es ist die Antwort auf „wann haben wir das gemacht und warum".

**Der Status wird laufend gepflegt, nicht am Ende.** Was du gerade bearbeitest, steht auf *In Arbeit*, bevor du anfängst — nicht danach. Ein Board, das erst beim Aufräumen stimmt, beantwortet die Frage nicht, für die es da ist.

**Große Vorhaben brauchen keine eigene Struktur**, sondern denselben Meilenstein-Eintrag auf mehreren Vorgängen (z. B. „Release 2.0"). Phasen als Ordner oder Unterseitenketten sind verboten — sie werden zum Friedhof, sobald sich die Reihenfolge ändert.

**Verknüpfungen immer als Liste schreiben.** Über die Schnittstelle heißt das `"system": ["<id>"]`, nie `"system": "<id>"`. Ein Einzelwert wird zwar seit 1.6.9 beim Schreiben geradegezogen, ältere Stände tun das nicht — und dort ist der Schaden unauffällig: Die Zeile steht weiter in ihrer Spalte und der Filter findet sie, aber das System sieht sie nicht mehr und der Fortschritt zählt sie nicht mit.

#### Ein System zeigt seinen eigenen Fortschritt

An Systeme hängen abgeleitete Spalten, damit die Frage „wie weit ist das" an der Zeile selbst beantwortet wird und nicht durch Suchen im Board:

- **Vorgänge** — Rück-Relation auf *Vorgänge* über *System*
- **Offen** — Rollup `count` über diese Rück-Relation, Bedingung Status **is_not** [`erledigt`, `verworfen`]
- **Erledigt** — Rollup `count`, Bedingung Status **is** `erledigt`
- **Fortschritt** — Rollup `percent` mit derselben Bedingung, Anzeige „Balken"

Alle werden beim Lesen berechnet und nirgends gespeichert. Wer sie neu baut, baut sie genau so: Eine zweite, gepflegte Liste müsste bei jedem Schreiben von beiden Seiten nachgezogen werden, und die erste verpasste Aktualisierung lässt beide auseinanderlaufen, ohne dass man sagen könnte, welche stimmt.

Für den Balken **kein** Formel-Feld: Eine Formel müsste dividieren, und ein System ohne Vorgänge ist 0 von 0 — in dessen Spalte stünde dauerhaft eine Fehlermeldung. `percent` rechnet es ohne Division.

#### Ansichten statt eigener Boards

**Kein eigenes Board pro Projekt.** Ein Board pro System teilt dieselbe Datenbank in Sichten, die niemand mehr gemeinsam liest, und beim nächsten System fängt man von vorn an. Stattdessen Ansichten auf der einen Vorgänge-Datenbank:

- **Offen** — das Arbeitsbrett, gruppiert nach Status, **gefiltert auf Status ist nicht Erledigt und nicht Verworfen**. Ohne diesen Filter wächst die Erledigt-Spalte für immer und drängt die Arbeit an den Rand.
- **Nach System** — dasselbe Brett, gruppiert nach System: eine Spalte je Projekt.
- **Historie** — Tabelle, nur Erledigt, nach Datum. Dorthin schaut man, wenn jemand fragt „wann haben wir das gemacht".

#### Faustregeln

- **Etwas dauerhaft Beschreibendes → Unterseite am System. Etwas mit einem Ende → Vorgang.** Im Zweifel Vorgang: Er kostet nichts und schließt sich von selbst.
- **Kein Workspace pro Projekt.** Ein eigener Workspace entsteht erst, wenn ein Vorhaben ein eigenes Team mit eigener Zugriffsregelung braucht.
- Kleine Systeme (ein Skript, ein Werkzeug) bekommen genauso eine Zeile wie große — das Feld „Wenn es ausfällt" trägt den Unterschied, nicht die Ablagetiefe.
- Systeme in Betrieb tragen ein Datum in „Nächster Check", damit Wartung nicht erst auffällt, wenn etwas kaputt ist.
- Entscheidungen mit Begründung festhalten, nicht nur das Ergebnis. Auch die verworfenen: Warum etwas *nicht* gebaut wurde, fragt später niemand mehr nach, und genau das wird dann ein zweites Mal vorgeschlagen.
- Zugangsdaten, Token und Schlüssel gehören nie auf eine Seite — hier steht höchstens, wo sie liegen.
<!-- salt-entwicklung:end -->
