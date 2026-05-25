# Threat Model

fuin raises the cost of static APK analysis and common repackaging workflows. It is not a
secret-management system and it does not make client-side code impossible to inspect.

## Protects Against

- Casual static analysis with jadx, apktool, `strings`, and direct ZIP extraction.
- Simple patch-and-resign attempts when anti-tamper is enabled with a release keystore.
- Baseline rooted-device and emulator workflows when runtime checks are enabled.
- Direct inspection of bundled `.so` files and user assets when those encryption layers are enabled.

## Does Not Protect Against

- A determined attacker who controls the device and can inspect runtime memory.
- Runtime hooks that bypass root, emulator, or integrity checks before they execute.
- Extraction of `assets/key.bin`; the AES key is bundled inside the APK by design.
- Vulnerabilities in the original app, backend APIs, or game protocol.

## Recommended Release Settings

- Sign with a real release keystore and keep the keystore outside the repository.
- Enable root detection, emulator detection, native library encryption, and asset encryption.
- Enable string obfuscation selectively for sensitive constants.
- Enable `FUIN_STRICT_MANIFEST_PATCH=true` so packing fails if the manifest cannot be patched.
- Enable `FUIN_VERIFY_SIGNATURE=true` in CI when Android build-tools are available.
- Run the packed APK on a real device or emulator before publishing.

## Operational Notes

- Apps without an explicit `android:name` on `<application>` currently require a manifest patcher
  that can insert a new attribute. fuin fails closed by default when it cannot confirm the stub
  application was inserted.
- The pure-Python signing fallback is useful for local smoke tests. Release pipelines should prefer
  Android build-tools `apksigner` and verify the final APK.
