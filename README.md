<div align="center">

<img src="docs/logo.png" alt="fuin logo" width="600">

**Android APK Packer — protect bytecode, block cheating, resist reverse engineering**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/)
[![CI](https://github.com/ykus4/fuin/actions/workflows/ci.yml/badge.svg)](https://github.com/ykus4/fuin/actions/workflows/ci.yml)

Protect any Android APK — Unity, Flutter, or standard — against cheating, piracy, and reverse engineering.
DEX bytecode, native libraries (.so), and assets are encrypted with AES-256-GCM.
Anti-tamper, root detection, and emulator blocking guard against runtime instrumentation tools like Frida and Xposed.
No source changes. No network at runtime. Works fully offline.

</div>

---

## Pack time

fuin processes your APK once — via the web UI, REST API, or CLI. The original APK is never modified in-place; a brand-new protected APK is produced.

```
┌─────────────────────────────────────────────────────────────────┐
│  📦 PACK TIME  (server or CLI)                                  │
│                                                                 │
│  your.apk                                                       │
│      │                                                          │
│      ├─ 📝 1. Patch AndroidManifest.xml  (binary AXML)          │
│      │         android:name → com.fuin.stub.StubApplication     │
│      │                                                          │
│      ├─ 🔐 2. Encrypt  classes.dex  (AES-256-GCM)               │
│      │         key   = os.urandom(32)  ← 256-bit, fresh each run│
│      │         nonce = os.urandom(12)  ← 96-bit                 │
│      │         output = nonce ‖ ciphertext ‖ GCM tag (16B)      │
│      │                                                          │
│      ├─ 🛡️ 3. Additional protections                            │
│      │         native libs (.so)  → encrypted                   │
│      │         user assets        → encrypted                   │
│      │         DEX strings        → XOR obfuscated (opt-in)     │
│      │         cert fingerprint   → embedded (anti-tamper)      │
│      │         security policy    → root/emulator detection     │
│      │                                                          │
│      ├─ 🔧 4. Rebuild APK                                       │
│      │         classes.dex                  ← stub DEX only     │
│      │         assets/encrypted.dex         ← ciphertext        │
│      │         assets/key.bin               ← AES key           │
│      │         assets/cert_fingerprint.bin  ← anti-tamper       │
│      │         assets/encrypted_libs/*      ← native libs       │
│      │         assets/encrypted_res/*       ← user assets       │
│      │         assets/security_policy.json  ← runtime policy    │
│      │                                                          │
│      └─ ✅ 5. zipalign → apksigner → report                     │
│                                                                 │
│  🔒 protected.apk  (no plaintext bytecode — only ciphertext)   │
└─────────────────────────────────────────────────────────────────┘
```

## Runtime

When the app launches on the end user's device, the stub decrypts the original bytecode silently in memory — no network call, no visible delay.

```
┌─────────────────────────────────────────────────────────────────┐
│  📱 RUNTIME  (on-device, no network required)                   │
│                                                                 │
│  StubApplication.attachBaseContext()                            │
│      │                                                          │
│      ├─ 🛡️ IntegrityCheck  — verify APK signing cert            │
│      │                                                          │
│      ├─ 🛡️ SecurityCheck   — root / emulator detection          │
│      │                                                          │
│      ├─ 📖 Read  assets/key.bin  +  assets/encrypted.dex        │
│      │                                                          │
│      ├─ 🔧 NativeLibDecryptor  — decrypt .so files              │
│      │                                                          │
│      ├─ 🔧 DecryptingAssetManager  — decrypt user assets        │
│      │                                                          │
│      ├─ 🔓 AES-256-GCM decrypt → plaintext DEX                  │
│      │       written to codeCacheDir  (chmod 0600)              │
│      │                                                          │
│      ├─ 🔤 StringDecryptor  — de-obfuscate DEX strings          │
│      │                                                          │
│      ├─ ⚙️  DexClassLoader  loads original classes              │
│      │                                                          │
│      └─ 🔄 ApplicationSwap  (reflection-based hot-swap)         │
│              stub Application → original Application            │
│                                                                 │
│  🚀 original Application.onCreate()  →  normal app launch      │
└─────────────────────────────────────────────────────────────────┘
```

## Demo

![fuin demo](docs/demo.gif)

## Features

### Anti-cheat & protection

| | |
|---|---|
| 🔐 **Static analysis resistant** | APK contains only ciphertext — no runnable bytecode visible to decompilers (jadx, apktool) |
| 🛡️ **Anti-tamper** | Verifies signing certificate at runtime — re-signed or patched APKs refuse to run |
| 🚫 **Root detection** | Blocks execution on rooted devices — defeats Magisk-based cheat tools |
| 📵 **Emulator detection** | Prevents running on emulators — blocks bot farms and automated exploit testing |
| 🔌 **Frida/Xposed resistant** | Root + emulator checks raise the bar against dynamic instrumentation frameworks |
| 📦 **Native lib encryption** | .so files (Unity/Unreal game engines, custom C++ libs) encrypted — binary analysis blocked |
| 🗂️ **Asset encryption** | Game configs, level data, databases encrypted at rest — resist asset extraction |
| 🔤 **String obfuscation** | DEX string constants XOR-encrypted — resist `strings` dumps and config harvesting |
| 🎮 **Unity & Flutter support** | Works out of the box with Unity `.so` libs and Flutter engine — no extra config |

### Developer experience

| | |
|---|---|
| 📴 **Fully offline** | Key is bundled in the APK — no network call at launch, no external dependency |
| 🌐 **Web UI + REST API** | Upload via browser or `curl`, download protected APK instantly |
| ⚡ **CLI support** | One-command local packing with `fuin-pack` |
| 🐳 **Docker-first** | No local Android SDK needed — everything runs in the image |
| 🔄 **SSE progress** | Real-time pack progress streamed to the browser |
| 📊 **Pack report** | Diff report showing size changes, encrypted targets, and metadata |
| 🔌 **Gradle plugin** | Auto-pack after `assembleRelease` with one DSL block |
| 🤖 **GitHub Actions** | Composite action for CI/CD pipelines |

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
# Basic usage
uv run fuin-pack pack input.apk output_protected.apk

# Full protection with all options
uv run fuin-pack pack input.apk output.apk \
  --root-detection \
  --emulator-detection \
  --encrypt-strings \
  --report

# Disable specific protections
uv run fuin-pack pack input.apk output.apk \
  --no-native-encrypt \
  --no-resource-encrypt
```

**CLI flags:**

| Flag | Description |
|------|-------------|
| `--report` | Print human-readable pack diff report |
| `--report-json` | Print pack diff report as JSON |
| `--root-detection` | Enable root detection at runtime |
| `--emulator-detection` | Enable emulator detection at runtime |
| `--encrypt-strings` | Enable DEX string obfuscation |
| `--no-native-encrypt` | Disable native library (.so) encryption |
| `--no-resource-encrypt` | Disable asset/resource encryption |
| `--no-strict-manifest-patch` | Allow best-effort packing when the manifest patch cannot be verified |
| `--verify-signature` | Run `apksigner verify` after signing |
| `--keystore` | Signing keystore path |
| `--key-alias` | Key alias |
| `--store-pass` | Keystore password |
| `--key-pass` | Key password |

---

## Gradle Plugin

Add fuin protection to your Android build pipeline with a single DSL block.

```kotlin
// settings.gradle.kts
pluginManagement {
    includeBuild("path/to/fuin/gradle-plugin")
}

// app/build.gradle.kts
plugins {
    id("com.fuin.packer")
}

fuin {
    enabled.set(true)

    // CLI mode (default)
    cliPath.set("/usr/local/bin/fuin-pack")

    // OR server mode
    // serverUrl.set("http://localhost:8000")
    // apiKey.set("your-api-key")

    // Signing
    keystore.set(file("release.keystore").absolutePath)
    keystoreAlias.set("release")
    keystorePassword.set(System.getenv("STORE_PASS"))
    keyPassword.set(System.getenv("KEY_PASS"))

    // Protection options
    rootDetection.set(true)
    emulatorDetection.set(true)
    encryptStrings.set(false)       // opt-in (slight runtime overhead)
    encryptNativeLibs.set(true)     // default: true
    encryptResources.set(true)      // default: true
}
```

After configuration, packing happens automatically after `assembleRelease`:

```bash
./gradlew assembleRelease   # → fuinPack runs automatically
```

---

## GitHub Actions

```yaml
- name: Pack APK with fuin
  uses: ykus4/fuin@main
  with:
    input-apk: app/build/outputs/apk/release/app-release.apk
    output-apk: app/build/outputs/apk/release/app-release-packed.apk
    keystore-base64: ${{ secrets.KEYSTORE_BASE64 }}
    keystore-alias: release
    keystore-password: ${{ secrets.STORE_PASS }}
    key-password: ${{ secrets.KEY_PASS }}
    root-detection: "true"
    emulator-detection: "true"
    encrypt-strings: "false"
```

---

## API reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Web UI |
| `POST` | `/analyze` | Analyze APK — list encryptable files without packing |
| `POST` | `/pack` | Upload APK → async job → `job_id` |
| `GET` | `/jobs/{id}/stream` | SSE progress (`text/event-stream`) |
| `GET` | `/jobs/{id}` | Poll job status |
| `GET` | `/apps/{id}/download` | Download protected APK |
| `POST` | `/apps/{id}/mapping/upload` | Upload ProGuard mapping.txt |
| `GET` | `/apps/{id}/mapping` | Download ProGuard mapping.txt |
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
| `FUIN_ROOT_DETECTION` | No | `false` | Enable root detection (server pipeline) |
| `FUIN_EMULATOR_DETECTION` | No | `false` | Enable emulator detection (server pipeline) |
| `FUIN_ENCRYPT_STRINGS` | No | `false` | Enable DEX string encryption (server pipeline) |
| `FUIN_STRICT_MANIFEST_PATCH` | No | `true` | Fail if `StubApplication` cannot be inserted into the manifest |
| `FUIN_VERIFY_SIGNATURE` | No | `false` | Run `apksigner verify` after signing |

---

## Repository structure

```
fuin/
├── fuin/                      # Python package
│   ├── config.py              # Config (env vars / .env)
│   ├── cli.py                 # fuin-pack CLI
│   ├── crypto.py              # AES-256-GCM
│   ├── manifest.py            # Binary AXML patcher
│   ├── apk.py                 # APK repack + zipalign + apksigner
│   ├── integrity.py           # Anti-tamper: cert fingerprint extraction
│   ├── native_lib.py          # Native library (.so) encryption
│   ├── resource_encrypt.py    # Asset/resource encryption
│   ├── string_encrypt.py      # DEX string XOR obfuscation
│   ├── report.py              # Pack diff report generation
│   ├── stub_dex.py            # Stub DEX locator
│   └── server/                # FastAPI server
│       ├── main.py            # HTTP endpoints (fuin-server)
│       ├── pipeline.py        # Pack pipeline
│       ├── jobs.py            # Async job store (SSE)
│       ├── models.py          # Pydantic response models
│       └── static/index.html  # Web UI
├── tests/                     # pytest suite
│   ├── conftest.py            # Shared fixtures (minimal APK, AXML builder)
│   ├── test_crypto.py         # AES-256-GCM roundtrip + tamper detection
│   ├── test_manifest.py       # AXML patcher
│   ├── test_apk.py            # inject, zipalign
│   ├── test_pipeline.py       # End-to-end pack pipeline
│   └── test_server.py         # FastAPI endpoints
├── stub/                      # Android stub (Kotlin, minSdk 24)
│   └── app/src/main/java/com/fuin/stub/
│       ├── StubApplication.kt      # Entry point: orchestrates all decryption
│       ├── Crypto.kt                # AES-256-GCM decryption
│       ├── ApplicationSwap.kt      # Reflection-based app hot-swap
│       ├── IntegrityCheck.kt       # Anti-tamper: cert verification
│       ├── SecurityCheck.kt        # Root/emulator detection
│       ├── NativeLibDecryptor.kt   # .so file decryption + lib path patching
│       ├── DecryptingAssetManager.kt  # Encrypted asset decryption
│       └── StringDecryptor.kt      # DEX string de-obfuscation
├── gradle-plugin/             # Gradle plugin for build integration
│   ├── build.gradle.kts
│   └── src/main/kotlin/com/fuin/gradle/
│       ├── FuinPlugin.kt      # Plugin entry point
│       ├── FuinExtension.kt   # DSL configuration
│       └── FuinPackTask.kt    # Pack task implementation
├── action.yml                 # GitHub Actions composite action
├── assets/
│   └── stub.dex               # pre-built stub DEX (committed)
├── .env.example
├── docker-compose.yml
└── Dockerfile
```

---

## Protection layers

fuin stacks multiple independent layers — defeating one does not defeat the others:

| Layer | Static Analysis | Cheating / Tampering | Reverse Engineering |
|-------|:-:|:-:|:-:|
| DEX encryption (AES-256-GCM) | ✅ Blocks jadx/apktool | — | Slows memory dumping |
| Native lib encryption | ✅ Blocks IDA/Ghidra | — | Slows binary analysis |
| Asset encryption | ✅ Blocks asset extraction | — | Slows config harvesting |
| String obfuscation | ✅ Blocks `strings` dumps | — | Slows constant harvesting |
| Anti-tamper (cert check) | — | ✅ Blocks APK repacking | ✅ Blocks patch-and-resign |
| Root detection | — | ✅ Blocks Magisk cheats | ✅ Blocks Frida/Xposed |
| Emulator detection | — | ✅ Blocks bot farms | ✅ Blocks automated exploit rigs |

---

## Security notes

- The AES key lives inside the APK (`assets/key.bin`). This defeats **static analysis** but not a determined attacker with a rooted device who can read app assets at runtime.
- Anti-tamper verifies the signing certificate, preventing APK re-signing and modification.
- Root/emulator detection provides a baseline defense against dynamic instrumentation (Frida, Xposed). Determined attackers can bypass these with Magisk Hide or custom ROMs.
- String encryption adds overhead to every string access — use selectively for sensitive strings.
- Use a real signing keystore (`FUIN_KEYSTORE_*`) for release builds.
- The binary AXML patcher (`fuin/manifest.py`) fails closed by default when it cannot confirm that `StubApplication` was inserted. For broader manifest rewriting support, consider [apktool](https://apktool.org/).
- See [Threat Model](docs/THREAT_MODEL.md) for the exact protection boundaries and recommended release settings.

---

## License

[MIT](LICENSE) © 2026 yotti
