# Configuration

fuin reads configuration from environment variables, and from a `.env` file in the
working directory. Copy `.env.example` to `.env` and set at minimum `FUIN_API_KEY` if
you run the server.

Settings are read **on every use**, not captured at import time, so changing the
environment takes effect without restarting a Python process.

---

## Server

Only the server reads these. The packer ignores them.

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `FUIN_API_KEY` | **yes** | — | API key for every endpoint except `GET /`. The server refuses to start without it. |
| `FUIN_PACKED_DIR` | no | `./data/packed_apks` | Where packed APKs and mapping files are written |
| `FUIN_DATABASE_URL` | no | `sqlite:///./data/fuin.db` | SQLAlchemy database URL |
| `FUIN_MAX_UPLOAD_MB` | no | `500` | Largest accepted APK upload, in MB |
| `FUIN_MAX_MAPPING_MB` | no | `50` | Largest accepted ProGuard mapping upload, in MB |
| `FUIN_CLEANUP_DAYS` | no | `30` | Delete packed apps older than this many days at startup. `0` disables cleanup. |
| `FUIN_WEBHOOK_URL` | no | — | Comma-separated URLs to POST to when a pack job finishes |
| `FUIN_WEBHOOK_ALLOW_HTTP` | no | `false` | Permit `http://` webhook targets as well as `https://` |

!!! warning "Webhook targets are validated"

    The webhook URL can also be supplied per request, which makes it a
    server-side request forgery vector. fuin therefore requires `https` and
    refuses any target that resolves to a private, loopback, link-local,
    reserved or multicast address — cloud instance-metadata endpoints included.
    Rejected URLs are dropped with a warning rather than failing the pack.

---

## Signing

Shared by the CLI and the server pipeline. If the path or either password is missing,
fuin generates a temporary debug keystore and logs a warning.

| Variable | Default | Description |
|---|---|---|
| `FUIN_KEYSTORE_PATH` | debug keystore | PKCS12 keystore to sign with |
| `FUIN_KEYSTORE_ALIAS` | `fuin` | Key alias |
| `FUIN_KEYSTORE_STORE_PASS` | — | Keystore password |
| `FUIN_KEYSTORE_KEY_PASS` | — | Key password |

!!! danger "Never ship a debug-signed build"

    Anti-tamper works by pinning the signing certificate. A debug keystore is
    generated fresh each run and its password is public, so an attacker can re-sign
    a modified APK and the check passes. Release builds must set `FUIN_KEYSTORE_*`
    or pass `--keystore`.

---

## Packing defaults

These seed the packer's options. **An explicit value from the CLI, the REST API or
the Gradle plugin always wins**; the environment only supplies the default when the
caller says nothing.

| Variable | Default | Description |
|---|---|---|
| `FUIN_ROOT_DETECTION` | `false` | Refuse to run on rooted devices |
| `FUIN_EMULATOR_DETECTION` | `false` | Refuse to run on emulators |
| `FUIN_ENCRYPT_STRINGS` | `false` | XOR-obfuscate DEX string constants |
| `FUIN_STRICT_MANIFEST_PATCH` | `true` | Fail the pack if `StubApplication` cannot be confirmed inserted |
| `FUIN_VERIFY_SIGNATURE` | `false` | Run `apksigner verify` after signing |
| `FUIN_STUB_DEX` | auto-detected | Path to a pre-built `stub.dex`, overriding the bundled one |

Booleans accept `1`, `true` or `yes`, case-insensitive. Anything else is false.

Integers must parse as integers — a malformed value raises a named error
(`FUIN_CLEANUP_DAYS must be an integer, got 'banana'`) rather than a bare traceback.

---

## Precedence

For the tri-state packing options:

```text
explicit argument  >  environment variable  >  built-in default
```

```bash
# environment supplies the default
FUIN_ROOT_DETECTION=true fuin-pack pack in.apk out.apk           # ON

# an explicit flag overrides it
FUIN_ROOT_DETECTION=true fuin-pack pack in.apk out.apk --root-detection   # ON
```

For keystore settings, an explicit `--keystore` overrides `FUIN_KEYSTORE_PATH`.

---

## Docker

`docker-compose.yml` reads `.env` and mounts a named volume at `/data`. The image
overrides two paths so state lands on the volume:

```dockerfile
ENV FUIN_PACKED_DIR=/data/packed_apks
ENV FUIN_DATABASE_URL=sqlite:////data/fuin.db
```

Set anything else in `.env`:

```bash title=".env"
FUIN_API_KEY=change-me
FUIN_ROOT_DETECTION=true
FUIN_EMULATOR_DETECTION=true
FUIN_CLEANUP_DAYS=7
```

---

## Database migrations

The server calls `create_all()` at startup, which is enough for a fresh install.
Deployments that upgrade across versions should run Alembic instead:

```bash
alembic upgrade head
```

`migrations/env.py` reads `FUIN_DATABASE_URL`, so the same environment configures
both.
