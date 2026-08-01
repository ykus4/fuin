# CLI

`fuin-pack` packs an APK locally. It needs no server and no database.

```bash
fuin-pack pack <input.apk> <output.apk> [options]
fuin-pack analyze <input.apk> [--json]
```

---

## `pack`

```bash
fuin-pack pack MyApp.apk MyApp-protected.apk --report
```

### Options

| Flag | Description |
|---|---|
| `--app-class` | Original `Application` class name. Usually auto-detected from the manifest; pass it when detection fails. |
| `--report` | Print a human-readable pack diff report |
| `--report-json` | Print the same report as JSON |
| `--root-detection` | Refuse to run on rooted devices |
| `--emulator-detection` | Refuse to run on emulators |
| `--encrypt-strings` | XOR-obfuscate DEX string constants |
| `--no-native-encrypt` | Do **not** encrypt native `.so` libraries |
| `--no-resource-encrypt` | Do **not** encrypt user assets |
| `--no-strict-manifest-patch` | Pack anyway when `StubApplication` cannot be verified as inserted |
| `--verify-signature` | Run `apksigner verify` after signing |
| `--keystore` | Signing keystore path (PKCS12) |
| `--key-alias` | Key alias |
| `--store-pass` | Keystore password |
| `--key-pass` | Key password |
| `-v`, `--verbose` | Debug logging |

### Flags and environment variables

The protection flags are **tri-state**. Omitting one defers to the matching
environment variable; passing it always wins.

```bash
# env decides
FUIN_ROOT_DETECTION=true fuin-pack pack in.apk out.apk     # root detection ON

# the flag decides
FUIN_ROOT_DETECTION=true fuin-pack pack in.apk out.apk --root-detection   # ON
```

This applies to `--root-detection`, `--emulator-detection`, `--encrypt-strings`,
`--verify-signature` and `--no-strict-manifest-patch`. See
**[Configuration](../reference/configuration.md)**.

### Signing

Without `--keystore`, fuin generates a throwaway debug keystore and warns:

```text
WARNING no keystore configured — using temporary debug keystore
```

That is fine for smoke tests. **Release builds must pass a real keystore** — a debug
key makes anti-tamper meaningless, since anyone can re-sign with the same well-known
key.

```bash
fuin-pack pack in.apk out.apk \
  --keystore release.keystore \
  --key-alias release \
  --store-pass "$STORE_PASS" \
  --key-pass "$KEY_PASS" \
  --verify-signature
```

Credentials can also come from `FUIN_KEYSTORE_*` environment variables, which keeps
them out of your shell history and process list.

---

## `analyze`

Reports what a pack *would* encrypt, without packing.

```bash
fuin-pack analyze MyApp.apk
```

```text
=== Fuin Encryption Analysis ===

DEX files (1 total, 4.2 MB):
  ✓ classes.dex  (4.2 MB)

Native libraries (3 total, 18.1 MB):
  ✓ lib/arm64-v8a/libunity.so  (12.0 MB)
  ...

--- Summary ---
  Total encryptable files: 12
  Total encryptable size:  24.6 MB
  APK total size:          31.0 MB
  Protection coverage:     79.4% of APK content
```

`--json` emits the same data as JSON for scripting:

```bash
fuin-pack analyze MyApp.apk --json | jq '.summary.coverage_percent'
```

---

## Exit behaviour

`fuin-pack` exits non-zero and prints a traceback on failure. Common causes:

| Message | Cause |
|---|---|
| `APK does not contain classes.dex` | The input is not an Android APK, or it is an app bundle (`.aab`) |
| `AndroidManifest.xml could not be patched with StubApplication` | No `android:name` on `<application>` to rewrite. Pass `--app-class`, or `--no-strict-manifest-patch` to pack anyway |
| `verify_signature is enabled but apksigner was not found` | `--verify-signature` without Android build-tools on `PATH` or `$ANDROID_HOME` |
