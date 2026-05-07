package com.fuin.stub

import android.content.Context
import android.os.Build
import android.util.Log
import org.json.JSONObject
import java.io.File

private const val TAG = "SecurityCheck"

/**
 * Root and emulator detection at runtime.
 *
 * Reads security_policy.json from assets to determine which checks to perform.
 * If a check fails, throws SecurityException to prevent decryption.
 */
object SecurityCheck {

    /**
     * Enforce security policy. Reads assets/security_policy.json and runs
     * enabled checks. No-op if the policy file is absent.
     */
    fun enforce(context: Context) {
        val policy = loadPolicy(context) ?: return

        if (policy.optBoolean("root_detection", false)) {
            if (isRooted()) {
                Log.e(TAG, "Root detected — aborting")
                throw SecurityException("This app cannot run on a rooted device")
            }
            Log.d(TAG, "Root check passed")
        }

        if (policy.optBoolean("emulator_detection", false)) {
            if (isEmulator()) {
                Log.e(TAG, "Emulator detected — aborting")
                throw SecurityException("This app cannot run on an emulator")
            }
            Log.d(TAG, "Emulator check passed")
        }
    }

    private fun loadPolicy(context: Context): JSONObject? {
        return try {
            val json = context.assets.open("security_policy.json").bufferedReader().readText()
            JSONObject(json)
        } catch (e: Exception) {
            null
        }
    }

    // --- Root Detection ---

    private fun isRooted(): Boolean {
        return checkSuBinary() || checkRootPackages() || checkRootProperties() || checkRootFiles()
    }

    private fun checkSuBinary(): Boolean {
        val paths = System.getenv("PATH")?.split(":") ?: emptyList()
        return paths.any { File(it, "su").exists() }
    }

    private fun checkRootPackages(): Boolean {
        val knownPackages = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
        )
        return knownPackages.any { pkg ->
            try {
                @Suppress("DEPRECATION")
                Runtime.getRuntime().exec(arrayOf("pm", "list", "packages", pkg))
                    .inputStream.bufferedReader().readText().contains(pkg)
            } catch (e: Exception) {
                false
            }
        }
    }

    private fun checkRootProperties(): Boolean {
        return try {
            val tags = Build.TAGS
            tags != null && tags.contains("test-keys")
        } catch (e: Exception) {
            false
        }
    }

    private fun checkRootFiles(): Boolean {
        val files = listOf(
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
        )
        return files.any { File(it).exists() }
    }

    // --- Emulator Detection ---

    private fun isEmulator(): Boolean {
        return checkEmulatorBuild() || checkEmulatorHardware() || checkQemuFiles()
    }

    private fun checkEmulatorBuild(): Boolean {
        return Build.FINGERPRINT.startsWith("generic") ||
            Build.FINGERPRINT.startsWith("unknown") ||
            Build.MODEL.contains("google_sdk") ||
            Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for x86") ||
            Build.MANUFACTURER.contains("Genymotion") ||
            Build.PRODUCT.contains("sdk") ||
            Build.PRODUCT.contains("vbox") ||
            Build.PRODUCT.contains("emulator") ||
            Build.HARDWARE.contains("goldfish") ||
            Build.HARDWARE.contains("ranchu")
    }

    private fun checkEmulatorHardware(): Boolean {
        return try {
            val prop = System.getProperty("ro.kernel.qemu")
            prop == "1"
        } catch (e: Exception) {
            false
        }
    }

    private fun checkQemuFiles(): Boolean {
        val files = listOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
        )
        return files.any { File(it).exists() }
    }
}
