<div align="center">

# 🔒 fuin

**Android APK Packer — protect bytecode from static analysis**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/)
[![CI](https://github.com/ykus4/fuin/actions/workflows/ci.yml/badge.svg)](https://github.com/ykus4/fuin/actions/workflows/ci.yml)

Upload an APK → get back a protected APK where `classes.dex` is AES-256-GCM encrypted.
No source changes. No network at runtime. Works fully offline.

</div>

---

## How it works

### Pack time

```mermaid
flowchart LR
    classDef input  fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef step   fill:#fef9c3,stroke:#f59e0b,color:#422006
    classDef output fill:#dcfce7,stroke:#22c55e,color:#14532d

    subgraph IN["📦 your.apk"]
        direction TB
        A1["AndroidManifest.xml"]:::input
        A2["classes.dex\n― plaintext bytecode ―"]:::input
        A3["res/  assets/  lib/  …"]:::input
    end

    subgraph FUIN["⚙️  fuin"]
        direction TB
        P1["① Patch AXML\nandroid:name → StubApplication"]:::step
        P2["② AES-256-GCM encrypt\n256-bit key  ·  96-bit nonce"]:::step
        P3["③ Inject stub DEX\n+ encrypted assets"]:::step
        P4["④ zipalign + apksign"]:::step
        P1 --> P2 --> P3 --> P4
    end

    subgraph OUT["🔒 protected.apk"]
        direction TB
        B1["AndroidManifest.xml\n(android:name patched)"]:::output
        B2["classes.dex  ← stub only"]:::output
        B3["assets/encrypted.dex\nnonce ‖ ciphertext ‖ GCM tag"]:::output
        B4["assets/key.bin\n256-bit AES key"]:::output
        B5["res/  assets/  lib/  …\n(unchanged)"]:::output
    end

    IN --> FUIN --> OUT
```

### Runtime (on-device, no network required)

```mermaid
flowchart TD
    classDef sys   fill:#f3e8ff,stroke:#a855f7,color:#3b0764
    classDef crypto fill:#fef9c3,stroke:#f59e0b,color:#422006
    classDef final fill:#dcfce7,stroke:#22c55e,color:#14532d

    LAUNCH([App launch]):::sys
    STUB["StubApplication\nattachBaseContext()"]:::sys
    READ["Read assets/key.bin\n+ assets/encrypted.dex"]:::sys
    DECRYPT["AES-256-GCM decrypt\n→ plaintext DEX\n(memory + codeCacheDir, chmod 0600)"]:::crypto
    LOAD["DexClassLoader\nload original classes"]:::sys
    SWAP["ApplicationSwap\nreflection hot-swap\nstub → original Application"]:::sys
    DONE(["original onCreate()\n✅ normal app launch"]):::final

    LAUNCH --> STUB --> READ --> DECRYPT --> LOAD --> SWAP --> DONE
```

> The decrypted DEX is written only to `codeCacheDir` (app-private sandbox, inaccessible to other apps) with owner-read-only permissions. It never touches external storage.

## Demo

![fuin demo](docs/demo.gif)

## Features

| | |
|---|---|
| 🔐 **Static analysis resistant** | APK contains only ciphertext — no runnable bytecode |
| 📴 **Fully offline** | Key is bundled in the APK, no network needed at launch |
| 🌐 **Web UI + REST API** | Upload via browser or `curl`, download protected APK instantly |
| ⚡ **CLI support** | One-command local packing with `fuin-pack` |
| 🐳 **Docker-first** | No local Android SDK needed — everything runs in the image |
| 🔄 **SSE progress** | Real-time pack progress streamed to the browser |

---

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/ykus4/fuin.git && cd fuin
cp .env.example .env          # set FUIN_API_KEY to any secret string
docker compose up --build
```

Open **http://localhost:8000**, drag-and-drop your APK, done.

> First build takes a few minutes (downloads Android build-tools + compiles stub DEX).
> Subsequent starts are instant. Packed APKs persist in a named Docker volume.

### Local setup

<details>
<summary>Expand for local setup (macOS)</summary>

```bash
# Dependencies
curl -LsSf https://astral.sh/uv/install.sh | sh
brew install openjdk@17

# Android build-tools 34 (zipalign + apksigner)
mkdir -p ~/android-sdk/build-tools
curl -L "https://dl.google.com/android/repository/build-tools_r34-macosx.zip" \
  -o /tmp/bt.zip
unzip -q /tmp/bt.zip -d /tmp/bt && mv /tmp/bt/android-14 ~/android-sdk/build-tools/34.0.0

# Build stub DEX (one-time)
cd stub && ./gradlew :app:assembleRelease && cd ..

# Start
uv sync
cp .env.example .env          # set FUIN_API_KEY
uv run fuin-server
```

fuin auto-discovers tools from `~/android-sdk/build-tools/` — no `PATH` changes needed.

</details>

---

## Usage

### Web UI

Go to `http://localhost:8000`:

1. Enter your API key → **Save**
2. Drag-and-drop an `.apk`
3. Watch the real-time progress bar
4. Click **Download packed APK**

### REST API

```bash
# Upload and pack
JOB=$(curl -sX POST http://localhost:8000/pack \
  -H "X-API-Key: $FUIN_API_KEY" \
  -F "file=@MyApp.apk" | jq -r .job_id)

# Stream progress
curl -N "http://localhost:8000/jobs/$JOB/stream?api_key=$FUIN_API_KEY"

# Download
curl -OJ http://localhost:8000/apps/{app_id}/download \
  -H "X-API-Key: $FUIN_API_KEY"
```

### CLI

```bash
uv run fuin-pack pack input.apk output_protected.apk
```

---

## API reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Web UI |
| `POST` | `/pack` | Upload APK → async job → `job_id` |
| `GET` | `/jobs/{id}/stream` | SSE progress (`text/event-stream`) |
| `GET` | `/jobs/{id}` | Poll job status |
| `GET` | `/apps/{id}/download` | Download protected APK |
| `GET` | `/apps` | List all packed apps |
| `DELETE` | `/apps/{id}` | Delete a packed app |

All endpoints except `GET /` require `X-API-Key` header (or `?api_key=` for SSE).

**SSE event format**
```json
{"status": "running", "step": "encrypting_dex", "pct": 40}
{"status": "done",    "step": "done",            "pct": 100, "result": {...}}
{"status": "error",   "step": "error",            "pct": 0,  "error": "..."}
```

---

## Configuration

Copy `.env.example` → `.env` and set at minimum `FUIN_API_KEY`.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FUIN_API_KEY` | **Yes** | — | API key for all server endpoints |
| `FUIN_KEYSTORE_PATH` | No | debug keystore | Signing keystore path |
| `FUIN_KEYSTORE_ALIAS` | No | `fuin` | Key alias |
| `FUIN_KEYSTORE_STORE_PASS` | No | — | Keystore password |
| `FUIN_KEYSTORE_KEY_PASS` | No | — | Key password |
| `FUIN_PACKED_DIR` | No | `./data/packed_apks` | Output dir for packed APKs |
| `FUIN_DATABASE_URL` | No | `sqlite:///./data/fuin.db` | SQLAlchemy DB URL |
| `FUIN_STUB_DEX` | No | auto-detected | Path to pre-built `stub.dex` |
| `FUIN_MAX_UPLOAD_MB` | No | `500` | Max APK upload size (MB) |
| `FUIN_CLEANUP_DAYS` | No | `30` | Auto-delete packed APKs older than N days (`0` = off) |
| `FUIN_WEBHOOK_URL` | No | — | POST to this URL when a pack job completes |

---

## Repository structure

```
fuin/
├── fuin/                   # Python package
│   ├── config.py           # Config (env vars / .env)
│   ├── cli.py              # fuin-pack CLI
│   ├── crypto.py           # AES-256-GCM
│   ├── manifest.py         # Binary AXML patcher
│   ├── apk.py              # APK repack + zipalign + apksigner
│   ├── stub_dex.py         # Stub DEX locator
│   └── server/             # FastAPI server
│       ├── main.py         # HTTP endpoints (fuin-server)
│       ├── pipeline.py     # Pack pipeline
│       ├── jobs.py         # Async job store (SSE)
│       └── static/index.html  # Web UI
├── stub/                   # Android stub (Kotlin, minSdk 24)
│   └── app/src/main/java/com/fuin/stub/
│       ├── StubApplication.kt
│       ├── Crypto.kt
│       └── ApplicationSwap.kt
├── .env.example
├── docker-compose.yml
└── Dockerfile
```

---

## Security notes

- The AES key lives inside the APK (`assets/key.bin`). This defeats **static analysis** but not a determined attacker with a rooted device who can read app assets at runtime.
- Use a real signing keystore (`FUIN_KEYSTORE_*`) for release builds.
- The binary AXML patcher (`fuin/manifest.py`) is best-effort. For production, consider [apktool](https://apktool.org/).

---

## License

[MIT](LICENSE) © 2026 yotti
