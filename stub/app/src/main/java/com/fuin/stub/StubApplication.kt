package com.fuin.stub

import android.app.Application
import android.content.Context
import android.util.Log
import dalvik.system.DexClassLoader
import java.io.File
import java.util.zip.ZipInputStream

private const val TAG = "StubApplication"

class StubApplication : Application() {

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)

        val key = base.assets.open("key.bin").readBytes()
        val encrypted = base.assets.open("encrypted.dex").readBytes()
        val decryptedDex = Crypto.decryptDex(encrypted, key)

        val dexDir = File(base.codeCacheDir, "fuin_dex").also { it.mkdirs() }

        // Write primary DEX
        val primaryDex = File(dexDir, "payload.dex").also {
            it.writeBytes(decryptedDex)
            it.setReadable(false, false)
            it.setReadable(true, true)
        }

        // Write extra DEX files (classes2.dex, classes3.dex, ...) if present
        val extraDexFiles = mutableListOf<File>()
        val assetNames = base.assets.list("") ?: emptyArray()
        if ("encrypted_extra.dex" in assetNames) {
            val encryptedExtra = base.assets.open("encrypted_extra.dex").readBytes()
            val extraBundle = Crypto.decryptDex(encryptedExtra, key)
            // Bundle is a ZIP containing classesN.dex entries
            ZipInputStream(extraBundle.inputStream()).use { zis ->
                var entry = zis.nextEntry
                while (entry != null) {
                    val outFile = File(dexDir, entry.name.replace("/", "_")).also { f ->
                        f.writeBytes(zis.readBytes())
                        f.setReadable(false, false)
                        f.setReadable(true, true)
                    }
                    extraDexFiles += outFile
                    Log.d(TAG, "extracted extra DEX: ${entry.name} → ${outFile.name}")
                    entry = zis.nextEntry
                }
            }
        }

        val originalAppClass = base.assets.open("original_app_class.txt")
            .bufferedReader().readText().trim()

        if (originalAppClass.isNotEmpty()) {
            Log.d(TAG, "swapping Application to $originalAppClass")

            // Build dex path list: primary + extras
            val dexPaths = (listOf(primaryDex) + extraDexFiles)
                .joinToString(File.pathSeparator) { it.absolutePath }

            val loader = DexClassLoader(dexPaths, dexDir.absolutePath, null, base.classLoader)
            @Suppress("UNCHECKED_CAST")
            val appClass = loader.loadClass(originalAppClass) as Class<out Application>
            ApplicationSwap.swap(this, appClass)
        }
    }
}
