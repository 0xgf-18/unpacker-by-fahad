package com.dpt.unpack.finalization

import java.io.File

/**
 * APK signing abstraction.
 *
 * Uses Android build-tools (zipalign + apksigner.jar) for signing.
 * Falls back gracefully if tools are unavailable.
 */
object ApkSigner {

    /**
     * Sign an APK file.
     *
     * Pipeline: align (optional) → sign → verify
     *
     * @param config signing configuration
     * @param inputApk the unsigned APK
     * @param outputApk the destination for the signed APK
     * @return signing result
     */
    fun sign(config: SigningConfig, inputApk: File, outputApk: File): SigningResult {
        val startTime = System.currentTimeMillis()
        val warnings = mutableListOf<String>()
        val errors = mutableListOf<String>()

        if (!inputApk.exists()) {
            return SigningResult(
                status = SigningStatus.FAILED,
                inputApk = inputApk,
                outputApk = null,
                errors = listOf("Input APK does not exist: ${inputApk.absolutePath}"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        if (!config.isValid) {
            return SigningResult(
                status = SigningStatus.FAILED,
                inputApk = inputApk,
                outputApk = null,
                errors = listOf("Invalid signing configuration: ${config.summary()}"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        if (!config.isBuildToolsAvailable) {
            return SigningResult(
                status = SigningStatus.MISSING_DEPENDENCY,
                inputApk = inputApk,
                outputApk = null,
                errors = listOf("Android build-tools not found. Set ANDROID_HOME or DPT_BUILD_TOOLS."),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        val buildTools = config.buildToolsDir!!

        // Step 1: Ensure keystore exists
        val keystore = ensureKeystore(config)
        if (keystore == null) {
            return SigningResult(
                status = SigningStatus.FAILED,
                inputApk = inputApk,
                outputApk = null,
                errors = listOf("Failed to generate keystore"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        // Step 2: Align (optional)
        val alignedApk = File(outputApk.parent, "aligned-${outputApk.name}")
        try {
            align(buildTools, inputApk, alignedApk)
        } catch (e: Exception) {
            warnings.add("Alignment skipped: ${e.message}")
            inputApk.copyTo(alignedApk, overwrite = true)
        }

        // Step 3: Sign
        try {
            signApk(buildTools, keystore, config, alignedApk)
        } catch (e: Exception) {
            alignedApk.delete()
            return SigningResult(
                status = SigningStatus.FAILED,
                inputApk = inputApk,
                outputApk = null,
                errors = listOf("Signing failed: ${e.message}"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        // Step 4: Verify signature
        val verified = try {
            verifySignature(buildTools, alignedApk)
            true
        } catch (e: Exception) {
            warnings.add("Signature verification failed: ${e.message}")
            false
        }

        // Step 5: Move to output
        alignedApk.copyTo(outputApk, overwrite = true)
        alignedApk.delete()

        return SigningResult(
            status = if (verified) SigningStatus.SUCCESS else SigningStatus.PARTIAL,
            inputApk = inputApk,
            outputApk = outputApk,
            warnings = warnings,
            errors = errors,
            timeMs = System.currentTimeMillis() - startTime,
            details = mapOf(
                "keystore" to keystore.absolutePath,
                "buildTools" to buildTools.absolutePath,
                "verified" to verified.toString(),
            ),
        )
    }

    private fun ensureKeystore(config: SigningConfig): File? {
        if (config.keystorePath.exists()) return config.keystorePath

        val keytool = findKeytool() ?: return null
        val parent = config.keystorePath.parentFile ?: return null
        parent.mkdirs()

        val cmd = listOf(
            keytool,
            "-genkeypair",
            "-alias", config.keyAlias,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-keystore", config.keystorePath.absolutePath,
            "-storepass", config.storePassword,
            "-keypass", config.keyPassword,
            "-dname", "CN=DPT-Dumper, OU=Tools, O=DPT-Dumper, L=NA, S=NA, C=NA",
        )
        runCommand(cmd)
        return if (config.keystorePath.exists()) config.keystorePath else null
    }

    private fun align(buildTools: File, input: File, output: File) {
        val zipalign = resolveTool(buildTools, "zipalign")
        if (!zipalign.exists()) {
            input.copyTo(output, overwrite = true)
            return
        }
        val cmd = listOf(zipalign.absolutePath, "-f", "-v", "4", input.absolutePath, output.absolutePath)
        runCommand(cmd)
    }

    private fun signApk(buildTools: File, keystore: File, config: SigningConfig, apk: File) {
        val apksigner = buildTools.resolve("lib/apksigner.jar")
        val java = findJava() ?: error("java not found")

        val cmd = listOf(
            java,
            "-jar", apksigner.absolutePath,
            "sign",
            "--ks", keystore.absolutePath,
            "--ks-key-alias", config.keyAlias,
            "--ks-pass", "pass:${config.storePassword}",
            "--key-pass", "pass:${config.keyPassword}",
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            apk.absolutePath,
        )
        runCommand(cmd)
    }

    private fun verifySignature(buildTools: File, apk: File) {
        val apksigner = buildTools.resolve("lib/apksigner.jar")
        val java = findJava() ?: error("java not found")

        val cmd = listOf(
            java,
            "-jar", apksigner.absolutePath,
            "verify",
            "--verbose",
            apk.absolutePath,
        )
        runCommand(cmd)
    }

    private fun findKeytool(): String? {
        val javaHome = System.getProperty("java.home") ?: return null
        val keytool = File(javaHome, "bin/keytool${if (isWindows()) ".exe" else ""}")
        return if (keytool.exists()) keytool.absolutePath else null
    }

    private fun findJava(): String? {
        val javaHome = System.getProperty("java.home") ?: return null
        val java = File(javaHome, "bin/java${if (isWindows()) ".exe" else ""}")
        return if (java.exists()) java.absolutePath else null
    }

    private fun resolveTool(buildTools: File, name: String): File {
        val ext = if (isWindows()) ".exe" else ""
        return buildTools.resolve("$name$ext")
    }

    private fun isWindows() = System.getProperty("os.name")?.lowercase()?.contains("win") == true

    private fun runCommand(cmd: List<String>) {
        val pb = ProcessBuilder(cmd)
        pb.redirectErrorStream(true)
        val process = pb.start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        if (exitCode != 0) {
            error("Command failed (exit $exitCode): ${cmd.firstOrNull()}\n$output")
        }
    }
}

enum class SigningStatus {
    SUCCESS,
    PARTIAL,
    FAILED,
    MISSING_DEPENDENCY,
    INVALID_INPUT,
    UNKNOWN,
}

data class SigningResult(
    val status: SigningStatus,
    val inputApk: File?,
    val outputApk: File?,
    val warnings: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
    val timeMs: Long = 0,
    val details: Map<String, String> = emptyMap(),
) {
    val isSuccess: Boolean get() = status == SigningStatus.SUCCESS
    val summary: String
        get() = buildString {
            append("[${status.name}] ")
            outputApk?.let { append(it.name) }
            if (errors.isNotEmpty()) append(" — ${errors.size} error(s)")
            if (warnings.isNotEmpty()) append(" — ${warnings.size} warning(s)")
        }
}
