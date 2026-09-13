# Vendored web assets (ADR-0008)

Nothing is loaded from a CDN: the console runs inside an overlay that may have no
internet access. Update by replacing the file and this table in one commit.

| File | Project | Version | SHA-256 | Bytes |
| --- | --- | --- | --- | --- |
| `fonts/geist.woff2` | [Geist](https://vercel.com/font) by Vercel, SIL OFL 1.1 — variable 400–600, latin subset as served by Google Fonts (v5) | 5 | `9b6f5ff45b278c744b5f379a2c4ecbaf858a842b8eaf82ac8d21b699ca16c608` | 29288 |
| `fonts/geist-mono.woff2` | [Geist Mono](https://vercel.com/font) by Vercel, SIL OFL 1.1 — variable 400–500, latin subset as served by Google Fonts (v6) | 6 | `5f3d6ad60f29d6cb708414ec6887163d63bf197377ef5417d2483ff31ace6c3b` | 23108 |

`style.css` and `mark.svg` are our own code, not vendored. They dress the login form,
which is the only page the server still renders; everything behind it is the app
(ADR-0013). htmx and the old console's `app.js` left with it on 13.09.2026.
