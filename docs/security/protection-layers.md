# Protection layers

fuin stacks independent layers. Defeating one does not defeat the others, and each
can be turned on or off separately.

| Layer | Static analysis | Cheating / tampering | Reverse engineering |
|---|:-:|:-:|:-:|
| DEX encryption (AES-256-GCM) | Blocks jadx/apktool | — | Slows memory dumping |
| Native lib encryption | Blocks IDA/Ghidra | — | Slows binary analysis |
| Asset encryption | Blocks asset extraction | — | Slows config harvesting |
| String obfuscation | Blocks `strings` dumps | — | Slows constant harvesting |
| Anti-tamper (cert check) | — | Blocks APK repacking | Blocks patch-and-resign |
| Root detection | — | Blocks Magisk cheats | Blocks Frida/Xposed |
| Emulator detection | — | Blocks bot farms | Blocks automated exploit rigs |

---

## DEX encryption

Always on. `classes.dex` is encrypted with AES-256-GCM using a fresh 256-bit key per
pack, and replaced by the stub DEX. Multidex APKs get `classes2.dex` and friends
bundled into a single encrypted archive.

A decompiler opening the packed APK sees only `com.fuin.stub.*`.

## Native library encryption

On by default; disable with `--no-native-encrypt`. Every `lib/**/*.so` is encrypted
and the plaintext removed. Matters most for Unity and Unreal titles, where game logic
often lives in `libil2cpp.so` or `libUE4.so` rather than in DEX.

## Asset encryption

On by default; disable with `--no-resource-encrypt`. User assets under `assets/` are
encrypted — game configs, level data, bundled databases. fuin's own assets are never
re-encrypted.

Use `exclude_files` (REST) or keep files out of `assets/` when something must stay
readable, for example a license file a third-party SDK reads directly.

## String obfuscation

Opt-in: `--encrypt-strings`. The DEX string data section is XOR-encrypted with a key
derived from the master key, and the DEX checksum and SHA-1 signature are repaired so
the runtime still accepts the file.

Costs a little overhead on string access, so enable it when constants are actually
sensitive — endpoint URLs, feature flags, license checks.

!!! note "The string key is derived from the master key"

    `assets/string_key.bin` is derived from `assets/key.bin`, which ships in the same
    APK. String obfuscation raises the cost of a `strings` dump; it does not add a
    second, independent secret.

## Anti-tamper

Enabled whenever a keystore is available. The SHA-256 of the signing certificate is
embedded at pack time; at launch the stub compares it against the certificate the APK
was actually signed with. A repacked and re-signed APK fails the check.

!!! danger "This only works with a real keystore"

    Without `FUIN_KEYSTORE_*` or `--keystore`, fuin signs with a freshly generated
    debug keystore whose password is public. An attacker can then re-sign a modified
    APK and pass the check. **Release builds must use a real keystore.**

## Root detection

Opt-in: `--root-detection`. The stub checks for common rooting artefacts and refuses
to start when it finds them. Aimed at Magisk-based cheat tooling and at the rooted
devices that Frida and Xposed usually require.

## Emulator detection

Opt-in: `--emulator-detection`. Blocks bot farms and automated exploit rigs, which
typically run on emulators.

!!! warning "Both detections are user-visible"

    An app that refuses to start on a rooted device will generate support tickets
    from legitimate power users. Decide deliberately whether that trade is worth it
    for your title.

---

## Recommended release configuration

```bash
fuin-pack pack app-release.apk app-release-packed.apk \
  --keystore release.keystore \
  --key-alias release \
  --store-pass "$STORE_PASS" \
  --key-pass "$KEY_PASS" \
  --root-detection \
  --emulator-detection \
  --verify-signature \
  --report
```

Keep `FUIN_STRICT_MANIFEST_PATCH=true` (the default) so a pack fails loudly rather
than shipping an APK where the stub was never wired in.

Then read the **[threat model](threat-model.md)** for what this does and does not
buy you.
