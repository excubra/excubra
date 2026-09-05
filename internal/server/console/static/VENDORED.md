# Vendored web assets (ADR-0008)

Nothing is loaded from a CDN: the console runs inside an overlay that may have no
internet access. Update by replacing the file and this table in one commit.

| File | Project | Version | SHA-256 | Bytes |
| --- | --- | --- | --- | --- |
| `htmx.min.js` | [htmx](https://htmx.org), BSD-2-Clause | 2.0.10 | `71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de` | 51238 |
