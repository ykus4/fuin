# Architecture

fuin has two halves: a **pack-time** pipeline that rewrites an APK, and a **runtime**
stub that undoes the encryption on device. They meet at a set of asset paths that
form the contract between the Python packer and the Kotlin stub.

---

## Pack time

The original APK is never modified in place; a brand-new protected APK is produced.

```text
┌─────────────────────────────────────────────────────────────────┐
│  PACK TIME  (server or CLI)                                     │
│                                                                 │
│  your.apk                                                       │
│      │                                                          │
│      ├─ 1. Patch AndroidManifest.xml  (binary AXML)             │
│      │       android:name → com.fuin.stub.StubApplication       │
│      │                                                          │
│      ├─ 2. Encrypt classes.dex  (AES-256-GCM)                   │
│      │       key   = os.urandom(32)   ← 256-bit, fresh each run │
│      │       nonce = os.urandom(12)   ← 96-bit                  │
│      │       output = nonce ‖ ciphertext ‖ GCM tag (16B)        │
│      │                                                          │
│      ├─ 3. Additional protections                               │
│      │       native libs (.so)  → encrypted                     │
│      │       user assets        → encrypted                     │
│      │       DEX strings        → XOR obfuscated (opt-in)       │
│      │       cert fingerprint   → embedded (anti-tamper)        │
│      │       security policy    → root/emulator detection       │
│      │                                                          │
│      ├─ 4. Rebuild the APK                                      │
│      │       classes.dex                  ← stub DEX only       │
│      │       assets/encrypted.dex         ← ciphertext          │
│      │       assets/key.bin               ← AES key             │
│      │       assets/cert_fingerprint.bin  ← anti-tamper         │
│      │       assets/encrypted_libs/*      ← native libs         │
│      │       assets/encrypted_res/*       ← user assets         │
│      │       assets/security_policy.json  ← runtime policy      │
│      │                                                          │
│      └─ 5. zipalign → apksigner → report                        │
│                                                                 │
│  protected.apk  (no plaintext bytecode — only ciphertext)       │
└─────────────────────────────────────────────────────────────────┘
```

Stages map to the progress events reported over
[SSE](../guide/rest-api.md#stream-progress).

---

## Runtime

At launch the stub decrypts in memory — no network call, no visible delay.

```text
┌─────────────────────────────────────────────────────────────────┐
│  RUNTIME  (on-device, no network required)                      │
│                                                                 │
│  StubApplication.attachBaseContext()                            │
│      │                                                          │
│      ├─ IntegrityCheck  — verify the APK signing certificate    │
│      │                                                          │
│      ├─ SecurityCheck   — root / emulator detection             │
│      │                                                          │
│      ├─ Read assets/key.bin + assets/encrypted.dex              │
│      │                                                          │
│      ├─ NativeLibDecryptor       — decrypt .so files            │
│      │                                                          │
│      ├─ DecryptingAssetManager   — decrypt user assets          │
│      │                                                          │
│      ├─ AES-256-GCM decrypt → plaintext DEX                     │
│      │       written to codeCacheDir (chmod 0600)               │
│      │                                                          │
│      ├─ StringDecryptor  — de-obfuscate DEX strings             │
│      │                                                          │
│      ├─ DexClassLoader loads the original classes               │
│      │                                                          │
│      └─ ApplicationSwap  (reflection-based hot-swap)            │
│              stub Application → original Application            │
│                                                                 │
│  original Application.onCreate()  →  normal app launch          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Asset contract

These paths are the interface between the packer and the stub. Changing one means
changing both.

| Asset | Contents |
|---|---|
| `assets/encrypted.dex` | The original `classes.dex`, AES-256-GCM |
| `assets/encrypted_extra.dex` | Multidex `classes2.dex`… bundled into one encrypted ZIP |
| `assets/key.bin` | The 256-bit AES key |
| `assets/original_app_class.txt` | The `Application` class to hot-swap back in |
| `assets/cert_fingerprint.bin` | SHA-256 of the signing certificate (anti-tamper) |
| `assets/security_policy.json` | Whether root and emulator detection are on |
| `assets/native_lib_manifest.json` | Which `.so` files were encrypted |
| `assets/encrypted_libs/*` | The encrypted `.so` files |
| `assets/res_map.json` | Which user assets were encrypted |
| `assets/encrypted_res/*` | The encrypted user assets |
| `assets/string_key.bin` | XOR key for DEX string de-obfuscation |

They are declared once in `src/fuin/contract.py`.

---

## Repository layout

```text
fuin/
├── src/fuin/                  # Python package (src layout)
│   ├── cli.py                 # fuin-pack entry point
│   ├── config.py              # packer settings
│   ├── packer.py              # end-to-end pack orchestration
│   ├── contract.py            # asset paths shared with the stub
│   ├── axml/                  # Android Binary XML — byte level only
│   │   ├── constants.py       #   chunk types, resource IDs
│   │   ├── reader.py          #   parsing primitives
│   │   ├── patcher.py         #   string-pool rewriting
│   │   └── info.py            #   read-only manifest inspection
│   ├── apk/                   # APK files — owns ZIP I/O and the SDK
│   │   ├── constants.py       #   ZIP and signing-block magics
│   │   ├── repack.py          #   inject stub + assets, patch manifest
│   │   ├── signing.py         #   apksigner + pure-Python v1/v2 fallback
│   │   ├── keystore.py        #   PKCS12 load, debug keystore, resolution
│   │   ├── zipalign.py        #   zipalign + pure-Python fallback
│   │   ├── stub_dex.py        #   locate or build the stub DEX
│   │   ├── tools.py           #   locate and run SDK build-tools
│   │   └── zip_tools.py       #   shared ZIP helpers
│   ├── encryption/            # what gets encrypted
│   │   ├── aes.py             #   AES-256-GCM
│   │   ├── dex_strings.py     #   DEX string obfuscation
│   │   ├── native_libs.py     #   .so encryption
│   │   └── resources.py       #   asset encryption
│   ├── reporting/
│   │   ├── analyze.py         #   encryptable-target preview
│   │   └── report.py          #   pack diff report
│   ├── assets/stub.dex        # pre-built stub, ships in the wheel
│   └── server/                # FastAPI service — `fuin[server]`
│       ├── main.py            # app assembly
│       ├── config.py          # server-only settings
│       ├── deps.py            # engine, session, repositories, auth
│       ├── database.py        # SQLAlchemy models
│       ├── repositories.py    # all ORM queries
│       ├── schemas.py         # Pydantic request/response models
│       ├── pipeline.py        # the only boundary into the core packer
│       ├── jobs.py            # in-memory job store
│       ├── background.py      # detached-task helper
│       ├── routers/           # HTTP routes by resource
│       ├── services/          # pack, cleanup, webhook
│       └── static/index.html  # web UI
├── jvm/
│   ├── stub/                  # Android stub (Kotlin, minSdk 24)
│   │   └── app/src/main/java/com/fuin/stub/
│   │       ├── StubApplication.kt        # entry point
│   │       ├── Crypto.kt                 # AES-256-GCM decryption
│   │       ├── ApplicationSwap.kt        # reflection hot-swap
│   │       ├── IntegrityCheck.kt         # cert verification
│   │       ├── SecurityCheck.kt          # root/emulator detection
│   │       ├── NativeLibDecryptor.kt     # .so decryption
│   │       ├── DecryptingAssetManager.kt # asset decryption
│   │       └── StringDecryptor.kt        # string de-obfuscation
│   └── gradle-plugin/         # Gradle plugin
├── migrations/                # Alembic
├── tests/
│   └── fixtures/              # AXML and APK builders
├── docs/                      # this site
├── action.yml                 # GitHub composite action
├── Dockerfile
└── docker-compose.yml
```

---

## Layering

**Core packer** (`src/fuin/`) knows nothing about HTTP or databases. It depends only
on `cryptography` and `python-dotenv`. Its four packages layer strictly downward:

```text
packer.py  →  apk/  →  axml/
           ↘  encryption/
           ↘  reporting/
```

`axml/` is purely byte-level — it never opens a ZIP or touches the filesystem, so it
can be tested against buffers alone. `apk/` owns all ZIP I/O and the Android SDK
toolchain; the manifest patch is an APK-level operation there
(`apk.patch_manifest`) wrapping the byte-level `axml.patch_axml`.

**Server** (`src/fuin/server/`) is layered:

```text
routers/  →  services/  →  repositories.py  →  database.py
                    ↘
                     pipeline.py  →  core packer
```

`pipeline.py` is the single boundary into the packer: nothing under `server/` imports
`fuin.packer`, `fuin.analyze` or `fuin.apk_info` directly.

**Stub** (`jvm/stub/`) is compiled to `stub.dex` and committed, so packing needs no
Android SDK. Rebuild it with `cd jvm/stub && ./gradlew :app:assembleRelease`, or point
[`FUIN_STUB_DEX`](configuration.md) at your own build.

---

## Fallbacks

fuin works without an Android SDK by reimplementing the two tools it needs:

| Tool | Fallback |
|---|---|
| `zipalign` | Pure-Python aligner for STORED entries |
| `apksigner` | Pure-Python v1 (JAR) and v2 (APK Signing Block) signing |

The SDK binaries are preferred whenever `find_build_tool` locates them on `PATH` or
under `$ANDROID_HOME/build-tools`. The fallbacks are meant for local smoke tests —
release pipelines should have real build-tools and set
[`FUIN_VERIFY_SIGNATURE=true`](configuration.md).
