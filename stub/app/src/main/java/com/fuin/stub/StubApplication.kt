package com.fuin.stub

import android.app.Application
import android.content.Context
import android.util.Log
import dalvik.system.DexClassLoader
import java.io.File

private const val TAG = "StubApplication"

class StubApplication : Application() {

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)

        val key = base.assets.open("key.bin").readBytes()
        val encrypted = base.assets.open("encrypted.dex").readBytes()
        val decryptedDex = Crypto.decryptDex(encrypted, key)

        val dexDir = File(base.codeCacheDir, "fuin_dex").also { it.mkdirs() }
        val dexFile = File(dexDir, "payload.dex").also {
            it.writeBytes(decryptedDex)
            it.setReadable(false, false)
            it.setReadable(true, true)
        }

        val originalAppClass = base.assets.open("original_app_class.txt")
            .bufferedReader().readText().trim()

        if (originalAppClass.isNotEmpty()) {
            Log.d(TAG, "swapping Application to $originalAppClass")
            val loader = DexClassLoader(dexFile.absolutePath, dexDir.absolutePath, null, base.classLoader)
            @Suppress("UNCHECKED_CAST")
            val appClass = loader.loadClass(originalAppClass) as Class<out Application>
            ApplicationSwap.swap(this, appClass)
        }
    }
}
