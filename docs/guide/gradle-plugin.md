# Gradle plugin

Pack automatically as part of your Android build. The plugin adds a `fuinPack` task
that runs after `assembleRelease`.

The plugin lives in `jvm/gradle-plugin` and is not published to a repository yet, so
include it as a composite build.

## Setup

```kotlin title="settings.gradle.kts"
pluginManagement {
    includeBuild("path/to/fuin/jvm/gradle-plugin")
}
```

```kotlin title="app/build.gradle.kts"
plugins {
    id("com.fuin.packer")
}

fuin {
    enabled.set(true)

    // Pick one backend:
    cliPath.set("/usr/local/bin/fuin-pack")     // CLI mode (default)
    // serverUrl.set("http://localhost:8000")   // or server mode
    // apiKey.set(System.getenv("FUIN_API_KEY"))

    // Signing — keep secrets out of the build file
    keystore.set(file("release.keystore").absolutePath)
    keystoreAlias.set("release")
    keystorePassword.set(System.getenv("STORE_PASS"))
    keyPassword.set(System.getenv("KEY_PASS"))

    // Protection
    rootDetection.set(true)
    emulatorDetection.set(true)
    encryptStrings.set(false)     // opt-in: costs a little runtime overhead
    encryptNativeLibs.set(true)   // default
    encryptResources.set(true)    // default
}
```

Then:

```bash
./gradlew assembleRelease    # fuinPack runs automatically afterwards
```

## Options

| Property | Type | Default | Description |
|---|---|---|---|
| `enabled` | Boolean | `true` | Turn the plugin off without removing it |
| `cliPath` | String | — | Path to the `fuin-pack` binary (CLI mode) |
| `serverUrl` | String | — | fuin server base URL (server mode) |
| `apiKey` | String | — | API key, required in server mode |
| `keystore` | String | debug keystore | Signing keystore path |
| `keystoreAlias` | String | — | Key alias |
| `keystorePassword` | String | — | Keystore password |
| `keyPassword` | String | — | Key password |
| `rootDetection` | Boolean | `false` | Block rooted devices |
| `emulatorDetection` | Boolean | `false` | Block emulators |
| `encryptStrings` | Boolean | `false` | XOR-obfuscate DEX strings |
| `encryptNativeLibs` | Boolean | `true` | Encrypt `.so` libraries |
| `encryptResources` | Boolean | `true` | Encrypt user assets |

## CLI mode vs server mode

**CLI mode** shells out to `fuin-pack` on the build machine. Simplest for local and
single-runner builds; the machine needs fuin installed.

**Server mode** uploads the APK to a running fuin server and downloads the result.
Useful when many build agents should share one packing host, or when the Android
build-tools live only on that host. Set `serverUrl` and `apiKey`.

If both are set, `serverUrl` takes precedence.

!!! warning "Do not hardcode secrets"

    `keystorePassword`, `keyPassword` and `apiKey` end up in the build script. Read
    them from the environment or from `~/.gradle/gradle.properties`, never from a
    file you commit.

!!! note "Release builds only"

    The task hooks `assembleRelease`. Debug builds are left alone so your normal
    debug loop stays fast.
