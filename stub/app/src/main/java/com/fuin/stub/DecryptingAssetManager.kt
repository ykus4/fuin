package com.fuin.stub

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.InputStream

private const val TAG = "DecryptingAssetManager"

/**
 * Manages decryption of encrypted assets at runtime.
 *
 * At pack time, user assets are encrypted and stored in assets/encrypted_res/.
 * A mapping file (assets/res_map.json) maps original paths to encrypted filenames.
 *
 * This class decrypts all encrypted assets to a cache directory at startup,
 * making them available via getDecryptedAsset().
 */
object DecryptingAssetManager {

    private var decryptedDir: File? = null
    private val pathMap = mutableMapOf<String, File>()

    /**
     * Initialize: decrypt all encrypted assets to cache.
     * No-op if no res_map.json is present.
     */
    fun init(context: Context, key: ByteArray) {
        val resMap = loadResMap(context) ?: return

        val cacheDir = File(context.codeCacheDir, "fuin_assets").also { it.mkdirs() }
        decryptedDir = cacheDir

        val keys = resMap.keys()
        var count = 0

        while (keys.hasNext()) {
            val originalPath = keys.next()
            val encryptedName = resMap.getString(originalPath)

            try {
                val encrypted = context.assets.open("encrypted_res/$encryptedName").readBytes()
                val decrypted = Crypto.decryptDex(encrypted, key)

                // Recreate directory structure under cache
                val relativePath = originalPath.removePrefix("assets/")
                val outFile = File(cacheDir, relativePath)
                outFile.parentFile?.mkdirs()
                outFile.writeBytes(decrypted)
                outFile.setReadable(true, true)

                pathMap[originalPath] = outFile
                pathMap[relativePath] = outFile // Also map without "assets/" prefix
                count++
            } catch (e: Exception) {
                Log.e(TAG, "failed to decrypt asset: $originalPath", e)
            }
        }

        if (count > 0) {
            Log.i(TAG, "decrypted $count assets to cache")
        }
    }

    /**
     * Get a decrypted asset as an InputStream.
     * Returns null if the asset was not encrypted (caller should fall back to normal AssetManager).
     */
    fun getDecryptedAsset(path: String): InputStream? {
        val file = pathMap[path] ?: pathMap["assets/$path"] ?: return null
        return if (file.exists()) FileInputStream(file) else null
    }

    /**
     * Check if a path corresponds to a decrypted asset.
     */
    fun hasDecryptedAsset(path: String): Boolean {
        return pathMap.containsKey(path) || pathMap.containsKey("assets/$path")
    }

    /**
     * List decrypted files in a given directory (relative to assets/).
     */
    fun listDecryptedAssets(path: String): Array<String>? {
        val dir = decryptedDir ?: return null
        val targetDir = if (path.isEmpty()) dir else File(dir, path)
        if (!targetDir.isDirectory) return null
        return targetDir.list()
    }

    private fun loadResMap(context: Context): JSONObject? {
        return try {
            val json = context.assets.open("res_map.json").bufferedReader().readText()
            JSONObject(json)
        } catch (e: Exception) {
            null
        }
    }
}
