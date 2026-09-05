# Webhook fixtures (contract v1)

One complete webhook body per event type, generated from the code by
`make fixtures`. Build your receiver against these before the first real event.

Every delivery carries three headers:

- `X-EX0-Event-Id` — the `event_id` of the body, stable across retries; deduplicate on it
- `X-EX0-Timestamp` — unix seconds of *this attempt*; reject if more than 5 minutes off
- `X-EX0-Signature` — `sha256=<hex>` of HMAC-SHA256(secret, timestamp + "." + body)

The body bytes are exactly the file contents (including the trailing newline).
Signatures below use the test secret `ex0-test-secret` and the timestamp `1757000000`.
Retries resend byte-identical bodies with a fresh timestamp and signature.
Answer `2xx` at once and process asynchronously; anything else is retried with
backoff for 24 hours.

| File | Type | Severity | Signature |
| --- | --- | --- | --- |
| `box.silent.json` | `box.silent` | critical | `sha256=e9a9e8dfc4a1cbe5f10dca3e4026113426d6a78940edcaf63bc149c6359daa7c` |
| `box.back.json` | `box.back` | info | `sha256=41206202d6027d88c3bc5487c60f794c57bbef0a0105af84e7ba8d633ab1199a` |
| `host.down.json` | `host.down` | warning | `sha256=c0654d39e062b26a13f4b7435caf68ae64d7c9bb99fb3d079cdb9629ec4b7236` |
| `host.up.json` | `host.up` | info | `sha256=f0fc9fb258536ffd1f6cb2482ca111adb2d357ec4159a84c6cd7f37b389d1b2d` |
| `device.new.json` | `device.new` | info | `sha256=d941fefdc13c06554dc601926b10ea74302ae69583b08dbc2429485ddeed76ce` |
| `device.gone.json` | `device.gone` | info | `sha256=4d1dadd148f8e46fd121827a2bf2b51301c12a4684b89f37f9c11101e98e7d6c` |
| `maintenance.started.json` | `maintenance.started` | info | `sha256=72dde2b2d97596ead61c292833938b61a0518afbb837cab609e480766fbf0a14` |
| `maintenance.ended.json` | `maintenance.ended` | info | `sha256=8b606ad7abf6df6561bc23eb567ebad105e69ca15eacb94127d6204a270b9c9d` |
| `test.ping.json` | `test.ping` | info | `sha256=a662c851cb538981a2f072df921f6fcec73e479889dbbdf1017f7aaaa22ef316` |

Verification in Go (copy it):

```go
mac := hmac.New(sha256.New, []byte(secret))
mac.Write([]byte(timestampHeader + "."))
mac.Write(body)
want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
ok := hmac.Equal([]byte(want), []byte(signatureHeader))
```
