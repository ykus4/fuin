package com.fuin.stub

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.security.MessageDigest

private const val TAG = "IntegrityCheck"

/**
 * Verifies APK signing certificate integrity at runtime.
 *
 * Compares the SHA-256 fingerprint of the current APK's signing certificate
 * against the expected fingerprint embedded at pack time (assets/cert_fingerprint.bin).
 * If the fingerprints don't match, the APK has been re-signed (tampered).
 */
object IntegrityCheck {

    /**
     * Verify that the APK's signing certificate matches the expected fingerprint.
     *
     * @param context Application context
     * @throws SecurityException if the certificate does not match (APK was re-signed)
     */
    fun verify(context: Context) {
        val expectedFingerprint = loadExpectedFingerprint(context) ?: run {
            Log.d(TAG, "No cert_fingerprint.bin found — skipping integrity check")
            return
        }

        val actualFingerprint = getSigningCertFingerprint(context)
        if (actualFingerprint == null) {
            throw SecurityException("Unable to retrieve APK signing certificate")
        }

        if (!expectedFingerprint.contentEquals(actualFingerprint)) {
            Log.e(TAG, "Certificate fingerprint mismatch — APK has been re-signed!")
            throw SecurityException("APK integrity check failed: signing certificate mismatch")
        }

        Log.d(TAG, "Integrity check passed")
    }

    private fun loadExpectedFingerprint(context: Context): ByteArray? {
        return try {
            context.assets.open("cert_fingerprint.bin").use { it.readBytes() }
        } catch (e: Exception) {
            null
        }
    }

    @Suppress("DEPRECATION")
    private fun getSigningCertFingerprint(context: Context): ByteArray? {
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

            val cert = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
            } else {
                packageInfo.signatures?.firstOrNull()?.toByteArray()
            }

            if (cert != null) {
                MessageDigest.getInstance("SHA-256").digest(cert)
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get signing cert", e)
            null
        }
    }
}
