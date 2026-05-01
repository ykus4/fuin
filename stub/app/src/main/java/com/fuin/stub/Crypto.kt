package com.fuin.stub

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object Crypto {
    private const val NONCE_LEN = 12
    private const val TAG_LEN = 128 // bits

    fun decryptDex(encrypted: ByteArray, keyHex: String): ByteArray {
        val key = hexToBytes(keyHex)
        val nonce = encrypted.copyOfRange(0, NONCE_LEN)
        val ciphertext = encrypted.copyOfRange(NONCE_LEN, encrypted.size)

        val secretKey = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_LEN, nonce))
        return cipher.doFinal(ciphertext)
    }

    private fun hexToBytes(hex: String): ByteArray {
        check(hex.length % 2 == 0) { "Invalid hex string" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
