# Vendored web assets (ADR-0008)

Nothing is loaded from a CDN: the console runs inside an overlay that may have no
internet access. Update by replacing the file and this table in one commit.

| File | Project | Version | SHA-256 | Bytes |
| --- | --- | --- | --- | --- |
| `htmx.min.js` | [htmx](https://htmx.org), BSD-2-Clause | 2.0.10 | `71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de` | 51238 |
| `fonts/geist.woff2` | [Geist](https://vercel.com/font) by Vercel, SIL OFL 1.1 — variable 400–600, latin subset as served by Google Fonts (v5) | 5 | `9b6f5ff45b278c744b5f379a2c4ecbaf858a842b8eaf82ac8d21b699ca16c608` | 29288 |
| `fonts/geist-mono.woff2` | [Geist Mono](https://vercel.com/font) by Vercel, SIL OFL 1.1 — variable 400–500, latin subset as served by Google Fonts (v6) | 6 | `5f3d6ad60f29d6cb708414ec6887163d63bf197377ef5417d2483ff31ace6c3b` | 23108 |

`app.js` and `icons.svg` are our own code, not vendored.
