# API reference

Base URL is wherever `fuin-server` listens — `http://localhost:8000` by default.
Interactive documentation is generated at `/docs` and `/redoc`.

## Authentication

Every endpoint except `GET /` requires the API key from
[`FUIN_API_KEY`](configuration.md):

```
X-API-Key: <key>
```

The SSE endpoint additionally accepts `?api_key=<key>`, because the browser
`EventSource` API cannot set request headers.

A missing or wrong key returns `401` with `{"detail": "Invalid API key"}`.

---

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Web UI |
| `POST` | `/analyze` | List encryptable files without packing |
| `POST` | `/pack` | Start a pack job, returns `job_id` |
| `GET` | `/jobs/{job_id}/stream` | SSE progress stream |
| `GET` | `/jobs/{job_id}` | Poll job status |
| `GET` | `/apps` | List packed apps |
| `GET` | `/apps/{app_id}/download` | Download the packed APK |
| `POST` | `/apps/{app_id}/mapping/upload` | Upload a ProGuard `mapping.txt` |
| `GET` | `/apps/{app_id}/mapping` | Download the ProGuard `mapping.txt` |
| `DELETE` | `/apps/{app_id}` | Delete an app, its APK and its mapping |

Usage examples live in the **[REST API guide](../guide/rest-api.md)**.

---

## Status codes

| Code | When |
|---|---|
| `200` | Success |
| `400` | The upload is not an `.apk`, or does not start with a ZIP local-header magic |
| `401` | Missing or incorrect API key |
| `404` | Unknown `app_id` or `job_id`, or the file is gone from disk |
| `413` | Upload exceeds `FUIN_MAX_UPLOAD_MB` / `FUIN_MAX_MAPPING_MB` |
| `422` | Malformed request body (FastAPI validation) |

Errors use FastAPI's shape:

```json
{ "detail": "App not found" }
```

---

## Schemas

### `JobAccepted`

Returned by `POST /pack`.

```json
{ "job_id": "9f0c1d3e-4a2b-..." }
```

### `JobStatus`

Returned by `GET /jobs/{job_id}`.

| Field | Type | Description |
|---|---|---|
| `job_id` | string | The job identifier |
| `status` | string | `pending` · `running` · `done` · `error` |
| `step` | string | Current pipeline stage |
| `pct` | int | 0–100 |
| `result` | object \| null | Present when `status` is `done` |
| `error` | string \| null | Present when `status` is `error` |

Progress steps, in order: `loading_stub` (5) → `patching_manifest` (20) →
`encrypting_dex` (40) → `injecting` (60) → `aligning` (75) → `signing` (85) →
`reporting` (97) → `done` (100).

### `PackedApp`

The `result` object of a completed job.

| Field | Type | Description |
|---|---|---|
| `app_id` | string | Use this to download or delete |
| `package_name` | string | From the patched manifest |
| `apk_signature` | string | SHA-256 of the packed APK |
| `analysis` | object | APK metadata gathered before packing |
| `report` | object \| null | Size and entry diff versus the original |

### `AppInfo`

An element of `GET /apps`.

| Field | Type | Description |
|---|---|---|
| `app_id` | string | Identifier |
| `package_name` | string | Android package |
| `apk_signature` | string | SHA-256 of the packed APK |
| `analysis` | object \| null | APK metadata |
| `has_mapping` | bool | Whether a `mapping.txt` is stored |
| `created_at` | string \| null | ISO 8601 timestamp |

---

## Operational notes

!!! warning "Single process only"

    The in-memory job store is process-local. Running `fuin-server` with more than
    one worker means `POST /pack` and `GET /jobs/{id}/stream` can land on different
    processes and the stream will 404. Status polling still works, because job state
    is mirrored to the database.

The in-memory store keeps at most 512 jobs, evicting finished ones oldest-first.
Evicting a finished job costs only its SSE stream — `GET /jobs/{id}` continues to
answer from the database until
[`FUIN_CLEANUP_DAYS`](configuration.md) removes the record.
