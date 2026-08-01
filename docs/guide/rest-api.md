# REST API

Packing over HTTP. Every endpoint except `GET /` requires the API key.

```bash
export FUIN_API_KEY=your-secret
```

Send it as the `X-API-Key` header. The SSE stream also accepts `?api_key=` in the
query string, because the browser `EventSource` API cannot set headers.

Interactive docs are served at `/docs` (Swagger) and `/redoc`.

---

## Pack an APK

```bash
curl -sX POST http://localhost:8000/pack \
  -H "X-API-Key: $FUIN_API_KEY" \
  -F "file=@MyApp.apk"
```

```json
{ "job_id": "9f0c1d3e-..." }
```

Packing runs in the background; the response returns immediately.

### Form fields

| Field | Type | Default | Description |
|---|---|---|---|
| `file` | file | — | The `.apk` to pack (required) |
| `app_class` | string | auto-detect | Original `Application` class |
| `webhook_url` | string | — | Comma-separated URLs to POST to on completion |
| `exclude_files` | string | — | Comma-separated entry names to leave unencrypted |
| `encrypt_native` | bool | `true` | Encrypt `.so` libraries |
| `encrypt_assets` | bool | `true` | Encrypt user assets |
| `encrypt_strings` | bool | env | XOR-obfuscate DEX strings |
| `root_detection` | bool | env | Block rooted devices |
| `emulator_detection` | bool | env | Block emulators |

Omitting `encrypt_strings`, `root_detection` or `emulator_detection` defers to the
corresponding [environment variable](../reference/configuration.md); sending an
explicit value always wins.

---

## Stream progress

```bash
curl -N "http://localhost:8000/jobs/$JOB/stream?api_key=$FUIN_API_KEY"
```

`text/event-stream`, one JSON object per event:

```json
{"status": "running", "step": "encrypting_dex", "pct": 40}
{"status": "done",    "step": "done",  "pct": 100, "result": {"app_id": "...", "...": "..."}}
{"status": "error",   "step": "error", "pct": 0,   "error": "APK does not contain classes.dex"}
```

The stream closes after a `done` or `error` event.

!!! warning "One consumer per stream"

    Events are consumed from a queue, so two clients watching the same job split the
    events between them rather than each seeing all. A client that connects *after*
    the job finished will not receive the terminal event either — poll
    `GET /jobs/{id}` instead.

## Poll status

```bash
curl -s "http://localhost:8000/jobs/$JOB" -H "X-API-Key: $FUIN_API_KEY"
```

```json
{
  "job_id": "9f0c1d3e-...",
  "status": "done",
  "step": "done",
  "pct": 100,
  "result": { "app_id": "...", "package_name": "com.example.app", "apk_signature": "...", "analysis": {} },
  "error": null
}
```

Polling is the durable path: job state is mirrored to the database, so it survives a
server restart and in-memory eviction. Use it rather than SSE for automation.

---

## Download the packed APK

```bash
curl -OJ "http://localhost:8000/apps/$APP_ID/download" -H "X-API-Key: $FUIN_API_KEY"
```

`$APP_ID` comes from `result.app_id` on a completed job.

## List packed apps

```bash
curl -s http://localhost:8000/apps -H "X-API-Key: $FUIN_API_KEY"
```

```json
[
  {
    "app_id": "...",
    "package_name": "com.example.app",
    "apk_signature": "3f2a...",
    "analysis": {},
    "has_mapping": true,
    "created_at": "2026-08-01T09:12:44"
  }
]
```

## ProGuard mapping

Keep the `mapping.txt` for a packed build alongside it, so crash reports stay
deobfuscatable.

```bash
# Upload
curl -X POST "http://localhost:8000/apps/$APP_ID/mapping/upload" \
  -H "X-API-Key: $FUIN_API_KEY" -F "file=@mapping.txt"

# Download
curl -OJ "http://localhost:8000/apps/$APP_ID/mapping" -H "X-API-Key: $FUIN_API_KEY"
```

## Delete

```bash
curl -X DELETE "http://localhost:8000/apps/$APP_ID" -H "X-API-Key: $FUIN_API_KEY"
```

Removes the database row, the packed APK and the mapping file.

---

## Analyze without packing

```bash
curl -sX POST http://localhost:8000/analyze \
  -H "X-API-Key: $FUIN_API_KEY" \
  -F "file=@MyApp.apk" | jq .summary
```

Same data as [`fuin-pack analyze`](cli.md#analyze). Nothing is stored.

---

## Webhooks

Pass `webhook_url` on `POST /pack`, or set
[`FUIN_WEBHOOK_URL`](../reference/configuration.md) globally, and fuin POSTs on
completion:

```json
{ "event": "pack.done", "result": { "app_id": "...", "package_name": "..." } }
```

Delivery is fire-and-forget: failures are logged, not retried.

---

## Full endpoint list

See **[API reference](../reference/api.md)** for status codes and error shapes.
