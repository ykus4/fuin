package com.fuin.stub

import android.util.Log
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection

private const val TAG = "KeyServerClient"

object KeyServerClient {
    fun requestKey(serverUrl: String, appId: String, deviceId: String, apkSignature: String): String {
        require(serverUrl.startsWith("https://")) {
            "Key server URL must use HTTPS, got: $serverUrl"
        }

        val url = URL("$serverUrl/key")
        val conn = url.openConnection() as HttpsURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true
            conn.connectTimeout = 10_000
            conn.readTimeout = 10_000

            val body = JSONObject().apply {
                put("app_id", appId)
                put("device_id", deviceId)
                put("apk_signature", apkSignature)
            }.toString()

            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body) }

            val code = conn.responseCode
            check(code == HttpURLConnection.HTTP_OK) {
                "Key server returned HTTP $code"
            }

            val response = conn.inputStream.bufferedReader(Charsets.UTF_8).readText()
            return JSONObject(response).getString("key")
        } catch (e: Exception) {
            Log.e(TAG, "Key request failed", e)
            throw e
        } finally {
            conn.disconnect()
        }
    }
}
