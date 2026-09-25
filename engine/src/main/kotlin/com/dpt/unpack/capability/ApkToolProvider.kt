package com.dpt.unpack.capability

import com.dpt.unpack.lsp.ExternalTool
import java.io.File

/**
 * Centralized APKTool provider. Manages apktool availability and provides
 * structured decode/build operations with validation.
 */
object ApkToolProvider {

    data class DecodeResult(
        val success: Boolean,
        val outputDir: File?,
        val error: String? = null,
        val elapsed: Long = 0,
    )

    data class BuildResult(
        val success: Boolean,
        val outputApk: File?,
        val error: String? = null,
        val elapsed: Long = 0,
    )

    fun isAvailable(): Boolean = DependencyManager.checkApkTool().available

    fun getToolInfo(): DependencyManager.ToolInfo = DependencyManager.checkApkTool()

    fun decode(
        apk: File,
        outputDir: File,
        timeout: Long = 120_000,
        log: (String) -> Unit = {},
    ): DecodeResult {
        val toolInfo = getToolInfo()
        if (!toolInfo.available) {
            return DecodeResult(false, null, toolInfo.reason, 0)
        }

        val start = System.currentTimeMillis()
        outputDir.deleteRecursively()
        outputDir.mkdirs()

        return try {
            log("Decoding APK with apktool...")
            ExternalTool.dalvikvmJarDir = toolInfo.path?.parentFile
            val apktool = ExternalTool.findApktool()
                ?: return DecodeResult(false, null, "apktool not available", System.currentTimeMillis() - start)

            ExternalTool.runApktool(apktool, "d", apk.absolutePath, "-o", outputDir.absolutePath, "-f")

            val manifest = File(outputDir, "AndroidManifest.xml")
            val smaliDir = outputDir.listFiles { f, _ -> f.isDirectory && f.name.startsWith("smali") }?.firstOrNull()

            if (!manifest.exists()) {
                DecodeResult(false, null, "decode produced no AndroidManifest.xml", System.currentTimeMillis() - start)
            } else if (smaliDir == null) {
                DecodeResult(false, null, "decode produced no smali directory", System.currentTimeMillis() - start)
            } else {
                log("Decoded successfully in ${System.currentTimeMillis() - start}ms")
                DecodeResult(true, outputDir, elapsed = System.currentTimeMillis() - start)
            }
        } catch (e: Exception) {
            DecodeResult(false, null, "decode failed: ${e.message}", System.currentTimeMillis() - start)
        }
    }

    fun build(
        decodedDir: File,
        outputApk: File,
        timeout: Long = 120_000,
        log: (String) -> Unit = {},
    ): BuildResult {
        val toolInfo = getToolInfo()
        if (!toolInfo.available) {
            return BuildResult(false, null, toolInfo.reason, 0)
        }

        val start = System.currentTimeMillis()
        outputApk.delete()

        return try {
            log("Building APK with apktool...")
            ExternalTool.dalvikvmJarDir = toolInfo.path?.parentFile
            val apktool = ExternalTool.findApktool()
                ?: return BuildResult(false, null, "apktool not available", System.currentTimeMillis() - start)

            ExternalTool.runApktool(apktool, "b", decodedDir.absolutePath, "-o", outputApk.absolutePath)

            if (!outputApk.exists() || outputApk.length() == 0L) {
                BuildResult(false, null, "build produced no output APK", System.currentTimeMillis() - start)
            } else {
                log("Built successfully in ${System.currentTimeMillis() - start}ms (${outputApk.length()} bytes)")
                BuildResult(true, outputApk, elapsed = System.currentTimeMillis() - start)
            }
        } catch (e: Exception) {
            BuildResult(false, null, "build failed: ${e.message}", System.currentTimeMillis() - start)
        }
    }

    fun capabilities(): Map<Capability.Cap, Capability.Status> {
        val tool = getToolInfo()
        return mapOf(
            Capability.Cap.APKTOOL to if (tool.available) {
                Capability.Status(true, version = tool.version)
            } else {
                Capability.Status(false, tool.reason)
            },
        )
    }
}
