package com.fuin.stub

import android.app.Application
import android.content.Context
import android.provider.Settings
import android.util.Log
import dalvik.system.DexClassLoader
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

private const val TAG = "StubApplication"
private const val KEY_FETCH_TIMEOUT_SEC = 30L

class StubApplication : Application() {

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)

        val serverUrl = base.getString(R.string.fuin_server_url)
        val appId = base.getString(R.string.fuin_app_id)

        val deviceId = Settings.Secure.getString(base.contentResolver, Settings.Secure.ANDROID_ID)
        val apkSignature = SignatureHelper.getApkSignatureSha256(base)

        // Fetch key on a background thread to avoid NetworkOnMainThreadException
        var keyHex: String? = null
        var fetchError: Throwable? = null
        val latch = CountDownLatch(1)

        Executors.newSingleThreadExecutor().execute {
            try {
                keyHex = KeyServerClient.requestKey(serverUrl, appId, deviceId, apkSignature)
            } catch (e: Exception) {
                fetchError = e
            } finally {
                latch.countDown()
            }
        }

        if (!latch.await(KEY_FETCH_TIMEOUT_SEC, TimeUnit.SECONDS)) {
            throw RuntimeException("Timed out waiting for decryption key from server")
        }
        fetchError?.let { throw RuntimeException("Failed to fetch decryption key", it) }

        val decryptedDex = Crypto.decryptDex(
            base.assets.open("encrypted.dex").readBytes(),
            keyHex!!,
        )

        val dexDir = File(base.codeCacheDir, "fuin_dex").also { it.mkdirs() }
        val dexFile = File(dexDir, "payload.dex").also {
            it.writeBytes(decryptedDex)
            it.setReadable(false, false)
            it.setReadable(true, true)
        }

        val originalAppClass = base.assets.open("original_app_class.txt")
            .bufferedReader().readText().trim()

        val loader = DexClassLoader(
            dexFile.absolutePath,
            dexDir.absolutePath,
            null,
            base.classLoader,
        )

        if (originalAppClass.isNotEmpty()) {
            Log.d(TAG, "swapping Application to $originalAppClass")
            @Suppress("UNCHECKED_CAST")
            val appClass = loader.loadClass(originalAppClass) as Class<out Application>
            ApplicationSwap.swap(this, appClass)
        }
    }
}
