# Web UI

The server bundles a single-page UI at `/`. It is the only endpoint that does not
require an API key — everything it then calls does.

Start it with Docker (see **[Installation](../getting-started/installation.md)**) and
open <http://localhost:8000>.

## Using it

1. **Enter your API key** — the value of `FUIN_API_KEY` — and press **Save**. It is
   kept in browser storage and sent as `X-API-Key` on every request.
2. **Drop an `.apk`** onto the upload area, or click to browse.
3. **Watch progress.** The UI subscribes to
   [`GET /jobs/{id}/stream`](rest-api.md#stream-progress) and shows each stage as it
   happens: `patching_manifest` → `encrypting_dex` → `injecting` → `aligning` →
   `signing` → `done`.
4. **Download** the packed APK when the job finishes.

## Packed app list

Below the uploader is the list of everything packed so far, backed by
[`GET /apps`](rest-api.md#list-packed-apps). For each app you can:

- Download the protected APK
- Upload a ProGuard `mapping.txt` to keep alongside it, and download it later
- Delete the app, which removes both the database row and the files on disk

Old entries are cleaned up automatically after
[`FUIN_CLEANUP_DAYS`](../reference/configuration.md) days.

## Limits

Uploads larger than [`FUIN_MAX_UPLOAD_MB`](../reference/configuration.md) (500 MB by
default) are rejected with `413`. Mapping files are capped separately by
`FUIN_MAX_MAPPING_MB` (50 MB).

!!! note "The UI is a client of the REST API"

    Nothing in the UI is privileged. Anything it does, you can do with `curl` — see
    **[REST API](rest-api.md)**.
