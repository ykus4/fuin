# Threat model

fuin raises the cost of static APK analysis and common repackaging workflows. It is
**not** a secret-management system, and it does not make client-side code impossible
to inspect.

!!! danger "The key ships inside the APK"

    `assets/key.bin` is bundled by design — that is what makes fuin work offline with
    no launch-time network call. It defeats static analysis. It does not defeat an
    attacker who controls the device and can read app assets or dump memory at
    runtime. If a value must stay secret from the device's owner, keep it on a
    server.

---

## Protects against

- Casual static analysis with jadx, apktool, `strings`, and direct ZIP extraction.
- Simple patch-and-resign attempts, when anti-tamper is enabled with a real release
  keystore.
- Baseline rooted-device and emulator workflows, when the runtime checks are enabled.
- Direct inspection of bundled `.so` files and user assets, when those encryption
  layers are enabled.

## Does not protect against

- A determined attacker who controls the device and can inspect runtime memory.
- Runtime hooks that bypass the root, emulator or integrity checks before they run.
- Extraction of `assets/key.bin` — the AES key is bundled inside the APK by design.
- Vulnerabilities in the original app, its backend APIs, or the game protocol.

---

## Recommended release settings

- Sign with a real release keystore, and keep the keystore out of the repository.
- Enable root detection, emulator detection, native library encryption and asset
  encryption.
- Enable string obfuscation selectively, for genuinely sensitive constants.
- Keep `FUIN_STRICT_MANIFEST_PATCH=true` so packing fails if the manifest cannot be
  patched.
- Set `FUIN_VERIFY_SIGNATURE=true` in CI, where Android build-tools are available.
- Run the packed APK on a real device or emulator before publishing.

See **[Protection layers](protection-layers.md)** for what each option costs and buys.

---

## Operational notes

- Apps without an explicit `android:name` on `<application>` need a manifest patcher
  that can insert a new attribute. fuin fails closed by default when it cannot
  confirm the stub Application was inserted. For broader manifest rewriting,
  consider [apktool](https://apktool.org/).
- The pure-Python signing fallback is useful for local smoke tests. Release pipelines
  should prefer Android build-tools `apksigner` and verify the final APK.
- String encryption adds overhead to every string access. Use it selectively.
- The decrypted DEX is written to `codeCacheDir` with mode `0600`. On a rooted device
  that is readable; this is the same exposure as the bundled key.

---

## Server deployment

The server is an internal build tool, not a public service:

- `FUIN_API_KEY` is a single shared secret with no scoping, rotation or rate
  limiting. Treat it like a CI token.
- Run it behind your own authentication and TLS termination if it is reachable
  beyond localhost.
- Uploaded APKs and packed outputs sit unencrypted on disk under `FUIN_PACKED_DIR`
  until `FUIN_CLEANUP_DAYS` removes them.
- Run a single worker process — see the
  [operational notes](../reference/api.md#operational-notes) in the API reference.

---

## Reporting a vulnerability

Open a [security advisory](https://github.com/ykus4/fuin/security/advisories/new)
rather than a public issue.
