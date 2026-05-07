package com.fuin.stub

import android.content.Context
import android.util.Log
import org.json.JSONArray
import java.io.File

private const val TAG = "NativeLibDecryptor"

/**
 * Decrypts encrypted native libraries (.so files) at runtime.
 *
 * At pack time, .so files from lib/<ABI>/ are encrypted and stored in
 * assets/encrypted_libs/. A manifest JSON lists the original paths and
 * encrypted filenames. At runtime, this class:
 * 1. Reads the manifest
 * 2. Determines which ABI the device needs
 * 3. Decrypts only the relevant .so files to a private directory
 * 4. Patches the native library path so System.loadLibrary() finds them
 */
object NativeLibDecryptor {

    /**
     * Decrypt native libraries and configure the library path.
     * No-op if no encrypted native libs are present.
     *
     * @param context Application context
     * @param key AES-256 decryption key
     */
    fun decryptAndLoad(context: Context, key: ByteArray) {
        val manifest = loadManifest(context) ?: return

        val nativeDir = File(context.codeCacheDir, "fuin_native").also { it.mkdirs() }
        val deviceAbis = android.os.Build.SUPPORTED_ABIS.toList()

        var decryptedCount = 0

        for (i in 0 until manifest.length()) {
            val entry = manifest.getJSONObject(i)
            val originalPath = entry.getString("original_path") // e.g. "lib/arm64-v8a/libfoo.so"
            val encryptedName = entry.getString("encrypted_name")

            // Extract ABI from path: lib/<abi>/libfoo.so
            val parts = originalPath.split("/")
            if (parts.size < 3) continue
            val abi = parts[1]
            val libName = parts.last()

            // Only decrypt libs for supported ABIs
            if (abi !in deviceAbis) continue

            try {
                val encrypted = context.assets.open("encrypted_libs/$encryptedName").readBytes()
                val decrypted = Crypto.decryptDex(encrypted, key)

                val abiDir = File(nativeDir, abi).also { it.mkdirs() }
                val outFile = File(abiDir, libName)
                outFile.writeBytes(decrypted)
                outFile.setReadable(true, false)
                outFile.setExecutable(true, false)
                decryptedCount++

                Log.d(TAG, "decrypted: $originalPath -> ${outFile.absolutePath}")
            } catch (e: Exception) {
                Log.e(TAG, "failed to decrypt $originalPath", e)
            }
        }

        if (decryptedCount > 0) {
            patchNativeLibraryPath(context, nativeDir, deviceAbis)
            Log.i(TAG, "decrypted $decryptedCount native libraries")
        }
    }

    private fun loadManifest(context: Context): JSONArray? {
        return try {
            val json = context.assets.open("native_lib_manifest.json").bufferedReader().readText()
            JSONArray(json)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Patch the app's native library directory so that System.loadLibrary()
     * picks up our decrypted .so files.
     */
    private fun patchNativeLibraryPath(context: Context, nativeDir: File, abis: List<String>) {
        try {
            // Find the best ABI directory
            val libDir = abis.map { File(nativeDir, it) }.firstOrNull { it.isDirectory && it.list()?.isNotEmpty() == true }
                ?: return

            // Patch ApplicationInfo.nativeLibraryDir
            val appInfo = context.applicationInfo
            val nativeLibField = appInfo.javaClass.getField("nativeLibraryDir")
            nativeLibField.isAccessible = true
            nativeLibField.set(appInfo, libDir.absolutePath)

            // Also patch the class loader's library path via reflection
            val pathList = getPathList(context.classLoader) ?: return
            val nativeLibDirsField = pathList.javaClass.getDeclaredField("nativeLibraryDirectories")
            nativeLibDirsField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val dirs = nativeLibDirsField.get(pathList) as? MutableList<File> ?: return
            dirs.add(0, libDir)
            nativeLibDirsField.set(pathList, dirs)

            // Update nativeLibraryPathElements if it exists (Android 6+)
            try {
                val makeElements = pathList.javaClass.getDeclaredMethod(
                    "makePathElements", List::class.java
                )
                makeElements.isAccessible = true
                val elements = makeElements.invoke(pathList, dirs)
                val elementsField = pathList.javaClass.getDeclaredField("nativeLibraryPathElements")
                elementsField.isAccessible = true
                elementsField.set(pathList, elements)
            } catch (e: NoSuchMethodException) {
                // Older Android — nativeLibraryDirectories is enough
            } catch (e: NoSuchFieldException) {
                // Field layout differs
            }

            Log.d(TAG, "patched native library path to: ${libDir.absolutePath}")
        } catch (e: Exception) {
            Log.w(TAG, "failed to patch native library path", e)
        }
    }

    private fun getPathList(classLoader: ClassLoader): Any? {
        return try {
            val field = Class.forName("dalvik.system.BaseDexClassLoader")
                .getDeclaredField("pathList")
            field.isAccessible = true
            field.get(classLoader)
        } catch (e: Exception) {
            null
        }
    }
}
