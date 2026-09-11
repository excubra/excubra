# EX0 console (single-page app)

The operator console served under `/app/` by the overlay listener. React 19,
TypeScript, Tailwind v4, shadcn/ui (radix-nova preset), TanStack Query and Table,
Recharts, cmdk, react-router. Why this stack and what it must never do:
[ADR-0013](../docs/adr/0013-console-spa.md).

## Build

```
make web          # from the repository root: builds into ../internal/server/console/webdist
make build        # runs `make web` first, then embeds the result into the Go binary
make web-check    # tsc + oxlint, no build
```

Node 22 with npm. `npm ci` runs automatically when `node_modules` is missing or older
than the lockfile.

## Develop

Vite serves the app with hot reload and proxies `/api`, `/login`, `/logout` to a Go
server on `127.0.0.1:18080`. The quickest backend is the preview server with KfT-like
sample data, which needs no password:

```
EX0_PREVIEW_SERVE=2h EX0_PREVIEW_ADDR=127.0.0.1:18080 \
  go test -tags preview -run TestPreviewServe -timeout 3h ./internal/server/console/ -v
```

It prints the session cookie to set in the browser. Then:

```
cd web && npm run dev
```

## Layout

| Path | What |
| --- | --- |
| `src/App.tsx` | shell: sidebar, header, routes, ⌘K palette |
| `src/pages/` | one file per screen |
| `src/components/` | our components; `ui/` is shadcn/ui as generated (`npx shadcn add …`) |
| `src/lib/api.ts` | fetch helpers and the TypeScript mirror of the JSON API |
| `src/lib/format.ts` | dates, durations, numbers in German |
| `src/index.css` | Tailwind, shadcn tokens, the green accent and the smaller radius |
