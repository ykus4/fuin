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
│   ├── pipeline.py         # Server-side pack pipeline (with progress callbacks)
│   ├── jobs.py             # In-memory async job store (SSE progress)
│   └── static/
│       └── index.html      # Web UI (drag-and-drop, progress bar, app list)
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
| pack / sign | `zipalign`, `apksigner` on PATH (Android SDK build-tools) |
| stub build | JDK 17+, Android SDK (build-tools ≥ 34), `ANDROID_HOME` set |

## Environment Setup

### 1. Install uv

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Install Android SDK (for zipalign / apksigner / stub build)

**macOS (Homebrew):**
```bash
brew install --cask android-commandlinetools
# then accept licenses
yes | sdkmanager --licenses
sdkmanager "build-tools;34.0.0"
```

**Linux:**
```bash
# Download commandlinetools from https://developer.android.com/studio#command-tools
# Extract to $HOME/android-sdk/cmdline-tools/latest/
export ANDROID_HOME=$HOME/android-sdk
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager "build-tools;34.0.0"
```

Add to your shell profile:
```bash
export ANDROID_HOME=$HOME/Library/Android/sdk   # macOS default
export PATH=$PATH:$ANDROID_HOME/build-tools/34.0.0
```

### 3. Install JDK 17+ (for stub build only)

```bash
# macOS
brew install openjdk@17

# Ubuntu/Debian
sudo apt install openjdk-17-jdk
```

## Getting Started

```bash
# 1. Clone
git clone https://github.com/yotti/fuin.git
cd fuin

# 2. Configure
cp .env.example .env
# Edit .env — at minimum set FUIN_API_KEY

# 3. Install Python dependencies
uv sync

# 4. Install git hooks
uv run pre-commit install

# 5. Build the stub DEX (requires Android SDK + JDK)
cd stub && ./gradlew :app:assembleRelease && cd ..
# The packer will auto-convert the AAR to stub.dex on first run.
# Alternatively: set FUIN_STUB_DEX=/path/to/stub.dex to skip the build.
```

## Configuration

All secrets are read from environment variables (or `.env`). See [.env.example](.env.example) for the full list.

| Variable | Required | Description |
|----------|----------|-------------|
| `FUIN_API_KEY` | Yes | API key for server endpoints |
| `FUIN_STUB_DEX` | No | Path to pre-built stub.dex (skips Gradle build) |
| `FUIN_KEYSTORE_PATH` | No | Signing keystore path (debug keystore used if unset) |
| `FUIN_KEYSTORE_ALIAS` | No | Key alias (default: `fuin`) |
| `FUIN_KEYSTORE_STORE_PASS` | No | Keystore password |
| `FUIN_KEYSTORE_KEY_PASS` | No | Key password |
| `FUIN_PACKED_DIR` | No | Output dir for packed APKs (default: `./packed_apks`) |
| `FUIN_DATABASE_URL` | No | SQLAlchemy DB URL (default: `sqlite:///./fuin.db`) |

## Usage

### Option A — Web UI (recommended)

```bash
uv run fuin-server
# Open http://localhost:8000
```

1. Enter your `FUIN_API_KEY` in the API Key field and click **Save**
2. Drag-and-drop your `.apk` onto the upload area
3. Watch the real-time progress bar
4. Click **Download packed APK** when complete

### Option B — REST API

Start the server:
```bash
uv run fuin-server
```

Upload and pack:
```bash
curl -X POST http://localhost:8000/pack \
  -H "X-API-Key: $FUIN_API_KEY" \
  -F "file=@MyApp.apk"
# → { "job_id": "..." }
```

Stream progress (SSE):
```bash
curl -N "http://localhost:8000/jobs/{job_id}/stream?api_key=$FUIN_API_KEY"
```

Download the protected APK:
```bash
curl -OJ http://localhost:8000/apps/{app_id}/download \
  -H "X-API-Key: $FUIN_API_KEY"
```

### Option C — CLI

```bash
uv run fuin-pack pack input.apk output_protected.apk
```

### Stub DEX

The packer needs a compiled stub DEX. Resolution order:

1. `FUIN_STUB_DEX=/path/to/stub.dex` env var
2. `fuin/stub.dex` pre-built artifact (committed or built once)
3. Auto-build via `stub/gradlew :app:assembleRelease` + `d8` (requires Android SDK + JDK)

## Web UI

Start the server and open `http://localhost:8000` in your browser:

- Enter your API key and save it (stored in `localStorage`)
- Drag-and-drop (or browse) an `.apk` file
- Watch the real-time progress bar as the APK is packed
- Click **Download packed APK** when complete
- Browse and manage all previously packed apps at the bottom

## Server API

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/` | Web UI |
| `POST` | `/pack` | Upload APK → start async job → return `job_id` |
| `GET`  | `/jobs/{job_id}/stream` | SSE progress stream (`text/event-stream`) |
| `GET`  | `/jobs/{job_id}` | Poll job status |
| `GET`  | `/apps/{app_id}/download` | Download protected APK |
| `GET`  | `/apps` | List all packed apps |
| `DELETE` | `/apps/{app_id}` | Delete a packed app |

All endpoints except `GET /` require `X-API-Key` header (or `?api_key=` query param for SSE).

### SSE event format

```json
{"status": "running", "step": "encrypting_dex", "pct": 40}
{"status": "done",    "step": "done",            "pct": 100, "result": {...}}
{"status": "error",   "step": "error",            "pct": 0,  "error": "..."}
```

## Security Notes

- The AES key is stored inside the APK (`assets/key.bin`). This protects against **static analysis** but not against a determined attacker with a rooted device who can read app assets at runtime.
- Use a real signing keystore (`FUIN_KEYSTORE_*`) for release builds — the debug keystore is for testing only.
- The binary AXML patcher in `fuin/manifest.py` is best-effort. For production, use [apktool](https://apktool.org/) or [androguard](https://github.com/androguard/androguard).
