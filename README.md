# fuin

Android DEX Packer — protect your APK's bytecode from static analysis via web-based packing.

## Overview

Upload an APK through the web API (or CLI). fuin encrypts `classes.dex` with AES-256-GCM,
embeds the key and ciphertext inside the APK itself, and replaces the Application class with
a minimal stub. At runtime the stub decrypts the DEX in memory and hands control back to the
original app — no network calls, no servers required at launch.

The protection goal is **static analysis resistance**: an attacker extracting the APK sees
only ciphertext, not runnable bytecode.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Pack time  (POST /pack  or  fuin-pack pack)                │
│                                                             │
│  Original APK                                               │
│      │                                                      │
│      ▼                                                      │
│  1. Patch AndroidManifest.xml                               │
│       android:name → com.fuin.stub.StubApplication          │
│      │                                                      │
│      ▼                                                      │
│  2. Encrypt classes.dex  (AES-256-GCM, random key)         │
│      │                                                      │
│      ▼                                                      │
│  3. Inject into APK                                         │
│       classes.dex                ← stub DEX                 │
│       assets/encrypted.dex       ← ciphertext               │
│       assets/key.bin             ← AES key                  │
│       assets/original_app_class.txt                         │
│      │                                                      │
│      ▼                                                      │
│  4. zipalign → apksigner                                    │
│                                                             │
│  Protected APK ────────────────────────────────────────────►│
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Runtime (on device — no network required)                  │
│                                                             │
│  StubApplication.attachBaseContext()                        │
│      │                                                      │
│      ▼                                                      │
│  Read assets/key.bin + assets/encrypted.dex                 │
│      │                                                      │
│      ▼                                                      │
│  AES-256-GCM decrypt → plaintext DEX (memory only)         │
│      │                                                      │
│      ▼                                                      │
│  DexClassLoader loads original classes                      │
│      │                                                      │
│      ▼                                                      │
│  ApplicationSwap replaces stub → original Application       │
│      │                                                      │
│      ▼                                                      │
│  original Application.onCreate() → normal app launch       │
└─────────────────────────────────────────────────────────────┘
```

## Features

- **Static analysis resistant** — APK contains only ciphertext; no plaintext DEX
- **No network at runtime** — key is bundled in the APK, launch works fully offline
- **Web-based packing** — upload via REST API, download protected APK instantly
- **Zero app changes** — original APK is packed as-is; no source modifications required

## Repository Structure

```
fuin/
├── .env.example            # Template — copy to .env and fill in values
├── pyproject.toml          # uv project — all Python dependencies
├── .pre-commit-config.yaml # ruff lint/format + general checks
│
├── fuin/                   # Python packer library + CLI
│   ├── config.py           # Shared config (env vars / .env)
│   ├── cli.py              # CLI entry point  (fuin-pack)
│   ├── crypto.py           # AES-256-GCM encrypt / decrypt
│   ├── manifest.py         # Binary AXML patcher
│   ├── apk.py              # APK repack, zipalign, apksigner
│   └── stub_dex.py         # Stub DEX builder / locator
│
├── server/                 # FastAPI packer server
│   ├── main.py             # HTTP endpoints  (fuin-server)
│   ├── database.py         # SQLAlchemy / SQLite
│   ├── models.py           # Pydantic request/response models
│   └── pipeline.py         # Server-side pack pipeline
│
└── stub/                   # Android stub (Kotlin, minSdk 24)
    └── app/src/main/java/com/fuin/stub/
        ├── StubApplication.kt   # Decrypts DEX and swaps Application
        ├── Crypto.kt            # AES-256-GCM decryption (javax.crypto)
        └── ApplicationSwap.kt   # Reflection-based Application hot-swap
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
| `FUIN_API_KEY` | Yes | API key for server endpoints |
| `FUIN_KEYSTORE_PATH` | No | Signing keystore path (debug keystore used if unset) |
| `FUIN_KEYSTORE_ALIAS` | No | Key alias (default: `fuin`) |
| `FUIN_KEYSTORE_STORE_PASS` | No | Keystore password |
| `FUIN_KEYSTORE_KEY_PASS` | No | Key password |
| `FUIN_PACKED_DIR` | No | Output dir for packed APKs (default: `./packed_apks`) |
| `FUIN_DATABASE_URL` | No | SQLAlchemy DB URL (default: `sqlite:///./fuin.db`) |

## Usage

### Option A — Server (recommended)

```bash
uv run fuin-server
```

Upload and pack:

```bash
curl -X POST http://localhost:8000/pack \
  -H "X-API-Key: $FUIN_API_KEY" \
  -F "file=@MyApp.apk"
# → { "app_id": "...", "package_name": "...", ... }
```

Download the protected APK:

```bash
curl -OJ http://localhost:8000/apps/{app_id}/download \
  -H "X-API-Key: $FUIN_API_KEY"
```

### Option B — CLI

```bash
uv run fuin-pack pack input.apk output_protected.apk
```

### Stub DEX

The packer needs a compiled stub DEX. Resolution order:

1. `FUIN_STUB_DEX=/path/to/stub.dex` env var
2. `fuin/stub.dex` pre-built artifact
3. Auto-build via `stub/gradlew assembleRelease` + `d8` (requires `ANDROID_HOME`)

## Server API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/pack` | Upload APK → pack → return app_id |
| `GET` | `/apps/{app_id}/download` | Download protected APK |
| `GET` | `/apps` | List all packed apps |
| `DELETE` | `/apps/{app_id}` | Delete a packed app |

All endpoints require `X-API-Key` header.

## Security Notes

- The AES key is stored inside the APK (`assets/key.bin`). This protects against **static analysis** but not against a determined attacker with a rooted device who can read app assets at runtime.
- Use a real signing keystore (`FUIN_KEYSTORE_*`) for release builds — the debug keystore is for testing only.
- The binary AXML patcher in `fuin/manifest.py` is best-effort. For production, use [apktool](https://apktool.org/) or [androguard](https://github.com/androguard/androguard).
