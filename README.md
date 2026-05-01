# fuin

Android DEX Packer — encrypt an APK's DEX at rest and protect it with server-managed keys.

## Overview

fuin takes an ordinary Android APK, encrypts its `classes.dex` with AES-256-GCM, and replaces
the original Application class with a lightweight stub. At runtime the stub fetches the
decryption key from a key-management server over HTTPS, decrypts the DEX in memory, loads it
with `DexClassLoader`, then hands control back to the original Application. The key never
touches the device's permanent storage.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Pack time (server-side via POST /pack, or CLI fuin-pack)       │
│                                                                 │
│  Original APK                                                   │
│      │                                                          │
│      ▼                                                          │
│  1. Patch AndroidManifest.xml                                   │
│       android:name → com.fuin.stub.StubApplication              │
│      │                                                          │
│      ▼                                                          │
│  2. Encrypt classes.dex  (AES-256-GCM, random key per APK)     │
│      │                                                          │
│      ▼                                                          │
│  3. Inject into APK                                             │
│       classes.dex                ← stub DEX (StubApplication)  │
│       assets/encrypted.dex       ← ciphertext                  │
│       assets/original_app_class.txt ← original class name      │
│      │                                                          │
│      ▼                                                          │
│  4. zipalign → apksigner                                        │
│      │                                                          │
│      ▼                                                          │
│  5. Register (package_name, AES key, APK SHA-256) in server DB │
│                                                                 │
│  Protected APK ───────────────────────────────────────────────►│
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Runtime (on device)                                            │
│                                                                 │
│  StubApplication.attachBaseContext()                            │
│      │                                                          │
│      ▼  (background thread)                                     │
│  POST /key  { app_id, device_id (ANDROID_ID), apk_signature }  │
│      │   Server verifies: not revoked, signature matches        │
│      ▼                                                          │
│  AES-256-GCM decrypt  assets/encrypted.dex  →  plaintext DEX  │
│      │                                                          │
│      ▼                                                          │
│  DexClassLoader  loads original classes from plaintext DEX      │
│      │                                                          │
│      ▼                                                          │
│  ApplicationSwap  replaces stub with original Application       │
│      │                                                          │
│      ▼                                                          │
│  original Application.onCreate()  →  normal app launch         │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Key never on disk** — AES key lives only in server DB and device RAM during decryption
- **Static analysis resistant** — extracted APK contains only ciphertext; no plaintext DEX
- **Tamper detection** — server validates APK SHA-256 signature on every key request
- **Device blocking** — any `ANDROID_ID` can be blocked server-side without an app update
- **Key revocation** — `DELETE /apps/{app_id}` instantly stops all new launches
- **Zero app changes** — original APK is packed as-is; no source modifications required
- **HTTPS enforced** — stub rejects non-HTTPS server URLs at runtime

## Repository Structure

```
fuin/
├── config.py               # Shared config (env vars / .env)
├── .env.example            # Template — copy to .env and fill in values
├── pyproject.toml          # uv project — all Python dependencies
├── uv.lock
├── .pre-commit-config.yaml # ruff lint/format + general checks
│
├── packer/                 # Python packer (CLI + library)
│   ├── main.py             # CLI entry point  (fuin-pack)
│   ├── crypto.py           # AES-256-GCM encrypt / decrypt
│   ├── manifest.py         # Binary AXML patcher
│   ├── apk.py              # APK repack, zipalign, apksigner
│   ├── stub_dex.py         # Stub DEX builder / locator
│   └── server_client.py    # Key server HTTP client
│
├── server/                 # FastAPI key management server
│   ├── main.py             # HTTP endpoints  (fuin-server)
│   ├── database.py         # SQLAlchemy / SQLite models
│   ├── models.py           # Pydantic request/response models
│   └── packer_pipeline.py  # Server-side pack pipeline
│
└── stub/                   # Android stub (Kotlin, minSdk 24)
    └── app/src/main/java/com/fuin/stub/
        ├── StubApplication.kt   # attachBaseContext — orchestrates boot
        ├── Crypto.kt            # AES-256-GCM decryption (javax.crypto)
        ├── KeyServerClient.kt   # HTTPS key request (HttpsURLConnection)
        ├── ApplicationSwap.kt   # Reflection-based Application hot-swap
        └── SignatureHelper.kt   # APK signature SHA-256 (API 28+ aware)
```

## Requirements

| Component | Requirement |
|-----------|-------------|
| packer / server | Python ≥ 3.12, [uv](https://github.com/astral-sh/uv) |
| stub build | Android SDK (build-tools ≥ 33), `ANDROID_HOME` set |
| pack / sign | `zipalign`, `apksigner` on PATH (from Android SDK) |

## Getting Started

```bash
# 1. Clone
git clone https://github.com/your-org/fuin.git
cd fuin

# 2. Configure
cp .env.example .env
# Edit .env — at minimum set FUIN_API_KEY

# 3. Install Python dependencies
uv sync

# 4. Install git hooks
uv run pre-commit install
```

## Configuration

All secrets are read from environment variables (or `.env`). See [.env.example](.env.example) for the full list.

| Variable | Required | Description |
|----------|----------|-------------|
| `FUIN_API_KEY` | Yes (server) | Admin API key for server endpoints |
| `FUIN_KEYSTORE_PATH` | No | Path to signing keystore (debug keystore used if unset) |
| `FUIN_KEYSTORE_ALIAS` | No | Key alias (default: `fuin`) |
| `FUIN_KEYSTORE_STORE_PASS` | No | Keystore password |
| `FUIN_KEYSTORE_KEY_PASS` | No | Key password |
| `FUIN_PACKED_DIR` | No | Output dir for packed APKs (default: `./packed_apks`) |
| `FUIN_DATABASE_URL` | No | SQLAlchemy DB URL (default: `sqlite:///./fuin.db`) |
| `FUIN_SERVER_URL` | No | Key server URL used by packer CLI |

## Usage

### Option A — Server-side (recommended)

Start the server:

```bash
uv run fuin-server
# Listening on http://0.0.0.0:8000
```

Upload an APK for packing:

```bash
curl -X POST http://localhost:8000/pack \
  -H "X-API-Key: $FUIN_API_KEY" \
  -F "file=@MyApp.apk" \
  -F "app_class=com.example.MyApplication"   # optional, auto-detected
# → { "app_id": "...", "package_name": "...", "apk_signature": "...", "analysis": {...} }
```

Download the protected APK:

```bash
curl -OJ http://localhost:8000/apps/{app_id}/download \
  -H "X-API-Key: $FUIN_API_KEY"
```

### Option B — CLI

```bash
uv run fuin-pack pack input.apk output_protected.apk
# Add --verbose for debug-level logging
```

### Stub DEX

The packer needs a compiled stub DEX. Resolution order:

1. `FUIN_STUB_DEX=/path/to/stub.dex` environment variable
2. `packer/stub.dex` pre-built artifact (committed or cached after first build)
3. Auto-build: `stub/gradlew assembleRelease` + `d8` (requires `ANDROID_HOME`)

## Server API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/pack` | API key | Upload APK → pack → return app_id |
| `GET` | `/apps/{app_id}/download` | API key | Download protected APK |
| `GET` | `/apps` | API key | List all registered apps |
| `POST` | `/apps` | API key | Register a manually packed APK |
| `DELETE` | `/apps/{app_id}` | API key | Revoke key (blocks all new launches) |
| `POST` | `/devices/block?device_id=...` | API key | Block a specific device ID |
| `POST` | `/key` | — | Runtime: device requests decryption key |

Authentication uses the `X-API-Key` header. Set `FUIN_API_KEY` in `.env`.

## Security Notes

- Deploy the server over HTTPS in production; the stub enforces HTTPS at runtime.
- The debug keystore is for testing only — set `FUIN_KEYSTORE_*` vars for release builds.
- `ANDROID_ID` can be spoofed on rooted devices. Consider adding Play Integrity API attestation for higher assurance.
- The binary AXML patcher in `manifest.py` is best-effort. For production, use [apktool](https://apktool.org/) or [androguard](https://github.com/androguard/androguard) for robust manifest manipulation.
