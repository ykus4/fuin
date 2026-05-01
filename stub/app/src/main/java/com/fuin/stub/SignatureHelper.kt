package com.fuin.stub

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

object SignatureHelper {
    fun getApkSignatureSha256(context: Context): String {
        val pm = context.packageManager
        val sigBytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            info.signingInfo.apkContentsSigners[0].toByteArray()
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                .signatures[0].toByteArray()
        }
        val hash = MessageDigest.getInstance("SHA-256").digest(sigBytes)
        return hash.joinToString("") { "%02x".format(it) }
    }
}
