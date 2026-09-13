# ADR-0013: The console is a single-page app, built at build time and embedded

Status: accepted · Date: 2026-09-11

## Context

The first console was server-rendered `html/template` with a vendored htmx for the few
live parts (ADR-0008, ADR-0011). That was right for the pilot, and it hit its ceiling as
soon as the product goal became concrete: one operator watching 100 customers with 20
to 100 devices each, later 1 000 customers, on a 32-inch screen that must stay readable
at a glance. That needs sortable, filterable, paginated tables, live-updating cards, a
command palette, charts, and later per-device logs and a place for the AI triage to show
its reasoning. Templates plus htmx get there only by re-implementing a component
framework by hand, and every review of the pilot console said the same thing: it looked
like a tool nobody would pay for.

Operating invariants still apply and are not negotiable: the console is reachable only
on the overlay listener (ADR-0009), there is no internet on that path, the server is one
static binary with zero external services, and the login flow (password, then TOTP) stays
server-rendered so a password manager can fill it and no secret ever passes through
JavaScript we did not write.

## Decision

1. **Stack.** Vite, React 19, TypeScript, Tailwind v4 and shadcn/ui (the dashboard
   example is the visual reference), TanStack Query for data loading, TanStack Table for
   tables, Recharts for charts, cmdk for the palette, react-router for client routing,
   Lucide icons, Geist as the one typeface. Everything lives in `web/`.
2. **Build-time only.** `make web` runs `scripts/web-build.sh`, which produces
   `internal/server/console/webdist/`; `go build` embeds that directory (`//go:embed`).
   Node is a build dependency, never a runtime one. The binary stays static and single.
   A checkout without Node still builds: the committed `webdist/unbuilt.html` is served
   under `/app/` with status 503 until someone runs `make web`. Built assets are not
   committed; CI and the release workflow build them.
3. **Serving.** The app is served under `/app/` by the overlay listener only, behind the
   same session cookie and CSRF token as before. Hashed assets are cached for a year,
   `index.html` is `no-store`. The CSP for `/app/` allows inline styles (component
   libraries need them) and nothing from other origins. Login, second factor and the
   CA download stay server-rendered pages outside the app.
4. **API.** The app talks to `/api/…` JSON endpoints on the same listener. Reads return
   the same view structs the templates used; writes reuse the existing form handlers,
   which answer `{ok, message}` when the request asks for JSON. Nothing in the API can do
   what the console could not do before; the Anti-Kaseya invariant (the server never
   triggers anything at the customer) is untouched.
5. **Dependencies.** The npm lockfile is authoritative (`npm ci`). A package needs a
   line in the table below, same rule as Go modules in ADR-0008. `oxlint` and `tsc`
   run in `make lint`. Nothing is loaded from a CDN; fonts are bundled.

### npm packages

| Package | Why |
| --- | --- |
| `react`, `react-dom`, `react-router` | the app and its client-side routing |
| `typescript`, `vite`, `@vitejs/plugin-react` | build |
| `tailwindcss`, `@tailwindcss/vite`, `tw-animate-css` | styling |
| `shadcn`, `radix-ui`, `cn`, `class-variance-authority` | shadcn/ui components and their runtime helpers |
| `lucide-react` | one icon family |
| `@fontsource-variable/geist` | the typeface, bundled instead of fetched |
| `@tanstack/react-query` | data loading, caching, background refresh |
| `@tanstack/react-table` | sortable, filterable, paginated tables that hold 1 000 rows |
| `recharts` | availability charts |
| `cmdk` | the ⌘K palette |
| `sonner`, `next-themes` | toasts (`next-themes` only because the shadcn toaster imports it) |
| `oxlint` | lint (dev) |
| `@types/*` | typings (dev) |

## Rejected

- **Keep templates + htmx and add JavaScript piecewise.** Ends up as a home-grown
  framework without tests or documentation; every table, palette and chart would be
  bespoke.
- **Preline or another Tailwind block collection.** Static markup to copy, not
  components to compose; shadcn/ui gives owned, typed components with the same look.
- **A separate frontend service or container.** Breaks "one binary, zero external
  services" and adds a second thing to deploy on a host that only has the overlay.
- **Committing the built assets.** Megabytes of minified JavaScript per commit and
  reviews that cannot see what changed. CI builds instead; the placeholder keeps
  `go build` working.
- **Loading libraries or fonts from a CDN.** The overlay has no internet, and the
  console would otherwise depend on somebody else's uptime and integrity.
- **Rewriting the login in the app.** A server-rendered form is what password managers
  and the second-factor flow (ADR-0011) are built for.

## Consequences

- `make build` needs Node 22; `go build` alone yields the placeholder console.
- The old server-rendered console pages are removed once nothing links to them; the
  login pages stay.
- Phase 2 (logs per device, rules, AI triage) gets its screens in the app; the API
  grows per feature, never a generic query endpoint.

## Amendment 2026-09-13: one console, at the root

The consequence above ("the old pages are removed once nothing links to them")
is now done: the app is served at `/` and the server-rendered console is gone —
fourteen templates, the vendored htmx, the old `app.js`, the icon sprite and
every page handler and its duplicate POST route, about 1700 lines. What stays
server-rendered is the login flow, the error page, `/ca.crt` and the assets
those need under `/static/` (they keep the strict CSP; the app's own policy
allows inline styles for the component library). `GET /app/…` answers 301 to
the same path at the root, so an old bookmark or a webhook link still lands in
the right place, and the links in webhook payloads (`/hosts/<id>`,
`/sites/<id>`) now open the app instead of a template.

Two things the merge brought to light: creating an API token or a webhook
target still rendered the deleted template, so the app never got its JSON and
the secret never appeared — both now answer `{ok, message, token|secret}`. And
the router's basename was pinned to `/app`, which the move made obvious
because nothing rendered at all.
