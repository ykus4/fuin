package com.fuin.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.asRequestBody
import java.io.File

/**
 * Gradle task that packs an APK using fuin.
 *
 * Supports two modes:
 * 1. CLI mode: shells out to `fuin-pack` binary
 * 2. Server mode: uploads APK to a fuin server via HTTP API
 */
abstract class FuinPackTask : DefaultTask() {

    @get:Internal
    lateinit var extension: FuinExtension

    @TaskAction
    fun pack() {
        val apkDir = File(project.buildDir, "outputs/apk/release")
        val apks = apkDir.listFiles { f -> f.extension == "apk" && !f.name.contains("packed") }
            ?: throw GradleException("No release APK found in ${apkDir.absolutePath}")

        if (apks.isEmpty()) {
            throw GradleException("No release APK found in ${apkDir.absolutePath}")
        }

        val inputApk = apks.first()
        val outputApk = File(inputApk.parent, inputApk.nameWithoutExtension + "_packed.apk")

        if (extension.serverUrl.isPresent) {
            packViaServer(inputApk, outputApk)
        } else {
            packViaCli(inputApk, outputApk)
        }

        logger.lifecycle("Fuin: packed APK -> ${outputApk.absolutePath}")
    }

    private fun packViaCli(input: File, output: File) {
        val cli = extension.cliPath.get()
        val cmd = mutableListOf(cli, "pack", input.absolutePath, output.absolutePath)

        if (extension.keystore.isPresent) {
            cmd += listOf("--keystore", extension.keystore.get())
        }
        if (extension.keystoreAlias.isPresent) {
            cmd += listOf("--key-alias", extension.keystoreAlias.get())
        }
        if (extension.keystorePassword.isPresent) {
            cmd += listOf("--store-pass", extension.keystorePassword.get())
        }
        if (extension.keyPassword.isPresent) {
            cmd += listOf("--key-pass", extension.keyPassword.get())
        }
        if (extension.rootDetection.getOrElse(false)) {
            cmd += "--root-detection"
        }
        if (extension.emulatorDetection.getOrElse(false)) {
            cmd += "--emulator-detection"
        }
        if (extension.encryptStrings.getOrElse(false)) {
            cmd += "--encrypt-strings"
        }
        if (!extension.encryptNativeLibs.getOrElse(true)) {
            cmd += "--no-native-encrypt"
        }
        if (!extension.encryptResources.getOrElse(true)) {
            cmd += "--no-resource-encrypt"
        }

        logger.lifecycle("Fuin: running ${cmd.joinToString(" ")}")

        val process = ProcessBuilder(cmd)
            .redirectErrorStream(true)
            .start()

        val output_text = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        if (exitCode != 0) {
            throw GradleException("fuin-pack failed (exit $exitCode):\n$output_text")
        }

        logger.info(output_text)
    }

    private fun packViaServer(input: File, output: File) {
        val serverUrl = extension.serverUrl.get().trimEnd('/')
        val apiKey = extension.apiKey.getOrElse("")

        if (apiKey.isEmpty()) {
            throw GradleException("fuin.apiKey must be set when using server mode")
        }

        logger.lifecycle("Fuin: uploading to $serverUrl/pack ...")

        // Use OkHttp for multipart upload
        val client = okhttp3.OkHttpClient.Builder()
            .callTimeout(java.time.Duration.ofMinutes(10))
            .build()

        val body = okhttp3.MultipartBody.Builder()
            .setType(okhttp3.MultipartBody.FORM)
            .addFormDataPart(
                "file",
                input.name,
                input.asRequestBody("application/vnd.android.package-archive".toMediaTypeOrNull())
            )
            .addFormDataPart("root_detection", extension.rootDetection.getOrElse(false).toString())
            .addFormDataPart("emulator_detection", extension.emulatorDetection.getOrElse(false).toString())
            .addFormDataPart("encrypt_strings", extension.encryptStrings.getOrElse(false).toString())
            .addFormDataPart("encrypt_native", extension.encryptNativeLibs.getOrElse(true).toString())
            .addFormDataPart("encrypt_assets", extension.encryptResources.getOrElse(true).toString())
            .build()

        val request = okhttp3.Request.Builder()
            .url("$serverUrl/pack")
            .header("X-API-Key", apiKey)
            .post(body)
            .build()

        val response = client.newCall(request).execute()
        if (!response.isSuccessful) {
            throw GradleException("Fuin server returned ${response.code}: ${response.body?.string()}")
        }

        val json = org.json.JSONObject(response.body!!.string())
        val jobId = json.getString("job_id")
        logger.lifecycle("Fuin: job started: $jobId")

        // Poll for completion
        var attempts = 0
        while (attempts < 120) {
            Thread.sleep(2000)
            val statusReq = okhttp3.Request.Builder()
                .url("$serverUrl/jobs/$jobId")
                .header("X-API-Key", apiKey)
                .get()
                .build()

            val statusResp = client.newCall(statusReq).execute()
            val statusJson = org.json.JSONObject(statusResp.body!!.string())
            val status = statusJson.getString("status")

            when (status) {
                "done" -> {
                    val appId = statusJson.getJSONObject("result").getString("app_id")
                    // Download packed APK
                    val dlReq = okhttp3.Request.Builder()
                        .url("$serverUrl/apps/$appId/download")
                        .header("X-API-Key", apiKey)
                        .get()
                        .build()
                    val dlResp = client.newCall(dlReq).execute()
                    output.writeBytes(dlResp.body!!.bytes())
                    return
                }
                "error" -> {
                    val error = statusJson.optString("error", "unknown error")
                    throw GradleException("Fuin pack failed: $error")
                }
            }
            attempts++
        }

        throw GradleException("Fuin pack timed out after 4 minutes")
    }
}
