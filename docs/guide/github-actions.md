# GitHub Action

fuin ships a composite action, so a release workflow can pack the APK it just built.

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

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `input-apk` | **yes** | — | Path to the APK to pack, relative to the workspace |
| `output-apk` | **yes** | — | Where to write the packed APK |
| `keystore-base64` | no | — | Base64-encoded PKCS12 keystore |
| `keystore-alias` | no | `fuin` | Key alias |
| `keystore-password` | no | — | Keystore password |
| `key-password` | no | — | Key password |
| `root-detection` | no | `false` | Block rooted devices |
| `emulator-detection` | no | `false` | Block emulators |
| `encrypt-strings` | no | `false` | XOR-obfuscate DEX strings |
| `no-native-encrypt` | no | `false` | Skip `.so` encryption |
| `no-resource-encrypt` | no | `false` | Skip asset encryption |
| `python-version` | no | `3.12` | Python to set up |

## Outputs

| Output | Description |
|---|---|
| `packed-apk` | Path to the packed APK (echoes `output-apk`) |

## Preparing the keystore secret

The action expects the keystore base64-encoded so it can live in a GitHub secret:

```bash
base64 -i release.keystore | pbcopy      # macOS
base64 -w0 release.keystore              # Linux
```

Store the result as `KEYSTORE_BASE64`. The action decodes it to a temp file and
deletes it afterwards, even if the run fails.

## Full workflow

```yaml
name: Release

on:
  push:
    tags: ["v*"]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - uses: actions/setup-java@v5
        with:
          distribution: temurin
          java-version: "17"

      - name: Build release APK
        run: ./gradlew assembleRelease

      - name: Pack APK with fuin
        uses: ykus4/fuin@main
        with:
          input-apk: app/build/outputs/apk/release/app-release.apk
          output-apk: app-release-packed.apk
          keystore-base64: ${{ secrets.KEYSTORE_BASE64 }}
          keystore-alias: release
          keystore-password: ${{ secrets.STORE_PASS }}
          key-password: ${{ secrets.KEY_PASS }}
          root-detection: "true"
          emulator-detection: "true"

      - uses: actions/upload-artifact@v4
        with:
          name: packed-apk
          path: app-release-packed.apk
```

!!! note "Paths are workspace-relative"

    `input-apk` and `output-apk` resolve against your repository checkout, not the
    action's own directory.

!!! warning "Pin the version you use"

    `@main` tracks whatever is on the default branch. For reproducible releases, pin
    a tag or commit SHA instead.
