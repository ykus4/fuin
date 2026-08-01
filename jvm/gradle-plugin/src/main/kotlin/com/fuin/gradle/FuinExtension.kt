package com.fuin.gradle

import org.gradle.api.provider.Property

/**
 * Configuration extension for the Fuin packer Gradle plugin.
 *
 * Usage in build.gradle.kts:
 * ```
 * fuin {
 *     enabled.set(true)
 *     serverUrl.set("http://localhost:8000")
 *     apiKey.set("your-api-key")
 *     // OR use CLI mode:
 *     cliPath.set("/usr/local/bin/fuin-pack")
 *     keystore.set(file("release.keystore").absolutePath)
 *     keystoreAlias.set("release")
 *     keystorePassword.set("password")
 *     keyPassword.set("password")
 *     rootDetection.set(true)
 *     emulatorDetection.set(true)
 *     encryptStrings.set(false)
 *     encryptNativeLibs.set(true)
 *     encryptResources.set(true)
 * }
 * ```
 */
abstract class FuinExtension {
    /** Enable/disable the plugin (default: true) */
    abstract val enabled: Property<Boolean>

    /** Fuin server URL for API-based packing */
    abstract val serverUrl: Property<String>

    /** API key for server authentication */
    abstract val apiKey: Property<String>

    /** Path to fuin-pack CLI binary (used when serverUrl is not set) */
    abstract val cliPath: Property<String>

    /** Signing keystore path */
    abstract val keystore: Property<String>

    /** Keystore key alias */
    abstract val keystoreAlias: Property<String>

    /** Keystore password */
    abstract val keystorePassword: Property<String>

    /** Key password */
    abstract val keyPassword: Property<String>

    /** Enable root detection */
    abstract val rootDetection: Property<Boolean>

    /** Enable emulator detection */
    abstract val emulatorDetection: Property<Boolean>

    /** Enable DEX string encryption */
    abstract val encryptStrings: Property<Boolean>

    /** Enable native library encryption */
    abstract val encryptNativeLibs: Property<Boolean>

    /** Enable resource/asset encryption */
    abstract val encryptResources: Property<Boolean>
}
