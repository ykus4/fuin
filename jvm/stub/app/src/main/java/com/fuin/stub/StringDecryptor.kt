package com.fuin.stub

import android.content.Context
import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

private const val TAG = "StringDecryptor"

/**
 * Decrypts XOR-obfuscated string data in DEX files.
 *
 * At pack time, the data section of the DEX is XOR'd with a derived key.
 * This class reverses the XOR before the DEX is loaded by DexClassLoader.
 *
 * The XOR key is stored in assets/string_key.bin and is derived from
 * the master AES key using SHA-256 chaining.
 */
object StringDecryptor {

    /**
     * Decrypt the string data section of a DEX file in-place.
     *
     * @param dexFile The DEX file to decrypt
     * @param context Application context (to read the XOR key from assets)
     */
    fun decryptDexStrings(dexFile: File, context: Context) {
        val xorKey = loadXorKey(context) ?: return

        try {
            RandomAccessFile(dexFile, "rw").use { raf ->
                val header = ByteArray(112)
                raf.readFully(header)

                val buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)

                // Verify DEX magic
                val magic = ByteArray(4)
                buf.get(magic)
                if (!magic.decodeToString().startsWith("dex")) {
                    Log.w(TAG, "Not a valid DEX file: ${dexFile.name}")
                    return
                }

                // Read data section offset and size from header
                buf.position(104)
                val dataSize = buf.int
                val dataOff = buf.int

                if (dataSize == 0 || dataOff == 0) return

                // Read the data section
                raf.seek(dataOff.toLong())
                val dataSection = ByteArray(minOf(dataSize, (raf.length() - dataOff).toInt()))
                raf.readFully(dataSection)

                // XOR decrypt
                val keyLen = xorKey.size
                for (i in dataSection.indices) {
                    dataSection[i] = (dataSection[i].toInt() xor xorKey[i % keyLen].toInt()).toByte()
                }

                // Write back
                raf.seek(dataOff.toLong())
                raf.write(dataSection)

                // Fix checksums
                fixDexChecksums(raf)
            }

            Log.d(TAG, "decrypted strings in ${dexFile.name}")
        } catch (e: Exception) {
            Log.e(TAG, "failed to decrypt strings in ${dexFile.name}", e)
        }
    }

    private fun loadXorKey(context: Context): ByteArray? {
        return try {
            context.assets.open("string_key.bin").readBytes()
        } catch (e: Exception) {
            null
        }
    }

    private fun fixDexChecksums(raf: RandomAccessFile) {
        // Read entire file for checksum calculation
        raf.seek(0)
        val allBytes = ByteArray(raf.length().toInt())
        raf.readFully(allBytes)

        // SHA-1 signature: covers bytes 32..EOF
        val sha1 = MessageDigest.getInstance("SHA-1").digest(allBytes.copyOfRange(32, allBytes.size))
        raf.seek(12)
        raf.write(sha1)

        // Reread with updated SHA-1 for Adler32
        raf.seek(0)
        raf.readFully(allBytes)

        // Adler32 checksum: covers bytes 12..EOF
        val checksum = adler32(allBytes, 12)
        val checksumBytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(checksum).array()
        raf.seek(8)
        raf.write(checksumBytes)
    }

    private fun adler32(data: ByteArray, offset: Int): Int {
        var a = 1
        var b = 0
        for (i in offset until data.size) {
            a = (a + (data[i].toInt() and 0xFF)) % 65521
            b = (b + a) % 65521
        }
        return (b shl 16) or a
    }
}
