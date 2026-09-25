package com.dpt.unpack.detection

import java.io.File
import java.util.zip.ZipFile

/**
 * Expanded static packer detection module.
 * Based on research: T07 (Generic Runtime Packing Detection), T11 (APK Structure Analysis).
 *
 * Detects additional packer families not covered by the Profiler, providing
 * comprehensive protection profiling for the Android app.
 *
 * Detects:
 * - Additional Chinese packers (Ali Protect, NetEase, OneHoff, etc.)
 * - More Jiagu variants
 * - DEX encryption patterns
 * - Suspicious native library loading patterns
 * - Dynamic loading API usage
 */
object StaticPackerDetector {

    data class DetectionResult(
        val packerId: String,
        val packerName: String,
        val confidence: Double,
        val evidence: List<String>,
        val category: String, // PACKER, PROTECTOR, OBFUSCATOR, RUNTIME
        val extractionMethod: String, // STATIC, DYNAMIC, EXTERNAL
        val requiredTools: List<String>,
    )

    /**
     * Analyzes an APK file for packer/protector signatures.
     * Returns a list of detection results sorted by confidence.
     */
    fun analyze(apk: File): List<DetectionResult> {
        val results = mutableListOf<DetectionResult>()

        ZipFile(apk).use { zip ->
            val entries = zip.entries().asSequence().map { it.name }.toList()
            val nativeLibs = entries
                .filter { it.contains("lib/") && it.endsWith(".so") }
                .map { it.substringAfterLast('/') }
            val dexBuffers = entries
                .filter { it.startsWith("classes") && it.endsWith(".dex") }
                .mapNotNull { e -> zip.getEntry(e)?.let { zip.getInputStream(it).readAllBytes() } }
            val dexTexts = dexBuffers.map { toLatin1(it) }
            val manifestBytes = zip.getEntry("AndroidManifest.xml")
                ?.let { zip.getInputStream(it).readAllBytes() }
            val manifestText = manifestBytes?.let { toLatin1(it) } ?: ""

            // Check each detection rule
            results.addAll(checkAliProtect(nativeLibs, dexTexts, manifestText, entries))
            results.addAll(checkNetEase(nativeLibs, dexTexts, manifestText))
            results.addAll(checkOneHoff(nativeLibs, dexTexts))
            results.addAll(checkDexGuard(nativeLibs, dexTexts))
            results.addAll(checkArxan(nativeLibs, dexTexts))
            results.addAll(checkGenericJiagu(nativeLibs, dexTexts, manifestText))
            results.addAll(checkDynamicLoading(dexTexts, nativeLibs))
            results.addAll(checkDexEncryption(dexBuffers, entries))
        }

        return results.sortedByDescending { it.confidence }
    }

    private fun checkAliProtect(
        nativeLibs: List<String>,
        dexTexts: List<String>,
        manifestText: String,
        entries: List<String>,
    ): List<DetectionResult> {
        val evidence = mutableListOf<String>()
        var confidence = 0.0

        val nativeMarkers = listOf("libmobisec.so", "libsgmain.so", "libsgsecuritybody.so")
        for (marker in nativeMarkers) {
            if (nativeLibs.any { it.contains(marker, ignoreCase = true) }) {
                evidence.add("native lib: $marker")
                confidence += 0.3
            }
        }

        val dexMarkers = listOf("com.alibaba.wireless.security", "com.alibaba.mobisec")
        for (marker in dexMarkers) {
            if (dexTexts.any { it.contains(marker, ignoreCase = true) }) {
                evidence.add("dex marker: $marker")
                confidence += 0.2
            }
        }

        if (manifestText.contains("com.alibaba.mobisec", ignoreCase = true)) {
            evidence.add("manifest: com.alibaba.mobisec")
            confidence += 0.2
        }

        return if (confidence > 0.0) listOf(DetectionResult(
            packerId = "ali_protect",
            packerName = "Ali Protect / Mobisec (阿里加固)",
            confidence = minOf(1.0, confidence),
            evidence = evidence,
            category = "PACKER",
            extractionMethod = "DYNAMIC",
            requiredTools = listOf("frida-server", "BlackDex"),
        )) else emptyList()
    }

    private fun checkNetEase(
        nativeLibs: List<String>,
        dexTexts: List<String>,
        manifestText: String,
    ): List<DetectionResult> {
        val evidence = mutableListOf<String>()
        var confidence = 0.0

        if (nativeLibs.any { it.contains("libnesec.so", ignoreCase = true) }) {
            evidence.add("native lib: libnesec.so")
            confidence += 0.4
        }

        if (dexTexts.any { it.contains("com.netease.nis", ignoreCase = true) }) {
            evidence.add("dex marker: com.netease.nis")
            confidence += 0.3
        }

        if (manifestText.contains("com.netease.nis", ignoreCase = true)) {
            evidence.add("manifest: com.netease.nis")
            confidence += 0.2
        }

        return if (confidence > 0.0) listOf(DetectionResult(
            packerId = "netease",
            packerName = "NetEase (网易易盾)",
            confidence = minOf(1.0, confidence),
            evidence = evidence,
            category = "PACKER",
            extractionMethod = "DYNAMIC",
            requiredTools = listOf("frida-server", "BlackDex"),
        )) else emptyList()
    }

    private fun checkOneHoff(
        nativeLibs: List<String>,
        dexTexts: List<String>,
    ): List<DetectionResult> {
        val evidence = mutableListOf<String>()
        var confidence = 0.0

        if (nativeLibs.any { it.contains("libOnehoff.so", ignoreCase = true) }) {
            evidence.add("native lib: libOnehoff.so")
            confidence += 0.4
        }

        if (dexTexts.any { it.contains("com.onehoff", ignoreCase = true) }) {
            evidence.add("dex marker: com.onehoff")
            confidence += 0.3
        }

        return if (confidence > 0.0) listOf(DetectionResult(
            packerId = "onehoff",
            packerName = "OneHoff (铠甲安全)",
            confidence = minOf(1.0, confidence),
            evidence = evidence,
            category = "PACKER",
            extractionMethod = "DYNAMIC",
            requiredTools = listOf("frida-server"),
        )) else emptyList()
    }

    private fun checkDexGuard(
        nativeLibs: List<String>,
        dexTexts: List<String>,
    ): List<DetectionResult> {
        val evidence = mutableListOf<String>()
        var confidence = 0.0

        if (nativeLibs.any { it.contains("libdexguard", ignoreCase = true) }) {
            evidence.add("native lib: libdexguard")
            confidence += 0.4
        }

        val markers = listOf("guardsquare", "com.guardsquare")
        for (marker in markers) {
            if (dexTexts.any { it.contains(marker, ignoreCase = true) }) {
                evidence.add("dex marker: $marker")
                confidence += 0.2
            }
        }

        return if (confidence > 0.0) listOf(DetectionResult(
            packerId = "dexguard",
            packerName = "DexGuard (Guardsquare)",
            confidence = minOf(1.0, confidence),
            evidence = evidence,
            category = "PROTECTOR",
            extractionMethod = "DYNAMIC",
            requiredTools = listOf("frida-server", "BlackDex"),
        )) else emptyList()
    }

    private fun checkArxan(
        nativeLibs: List<String>,
        dexTexts: List<String>,
    ): List<DetectionResult> {
        val evidence = mutableListOf<String>()
        var confidence = 0.0

        val nativeMarkers = listOf("libAppProtection.so", "libarx")
        for (marker in nativeMarkers) {
            if (nativeLibs.any { it.contains(marker, ignoreCase = true) }) {
                evidence.add("native lib: $marker")
                confidence += 0.4
            }
        }

        if (dexTexts.any { it.contains("com.arxan", ignoreCase = true) }) {
            evidence.add("dex marker: com.arxan")
            confidence += 0.2
        }

        return if (confidence > 0.0) listOf(DetectionResult(
            packerId = "arxan",
            packerName = "Arxan / AppProtection (Digital.ai)",
            confidence = minOf(1.0, confidence),
            evidence = evidence,
            category = "PROTECTOR",
            extractionMethod = "DYNAMIC",
            requiredTools = listOf("frida-server"),
        )) else emptyList()
    }

    private fun checkGenericJiagu(
        nativeLibs: List<String>,
        dexTexts: List<String>,
        manifestText: String,
    ): List<DetectionResult> {
        val evidence = mutableListOf<String>()
        var confidence = 0.0

        val nativeMarkers = listOf("libjiagu.so", "libjiagu_art.so", "libjiagu_x86.so")
        for (marker in nativeMarkers) {
            if (nativeLibs.any { it.contains(marker, ignoreCase = true) }) {
                evidence.add("native lib: $marker")
                confidence += 0.3
            }
        }

        val dexMarkers = listOf("com.jiagu.", "com.secneo.apkwrapper")
        for (marker in dexMarkers) {
            if (dexTexts.any { it.contains(marker, ignoreCase = true) }) {
                evidence.add("dex marker: $marker")
                confidence += 0.2
            }
        }

        if (manifestText.contains("com.jiagu.", ignoreCase = true) ||
            manifestText.contains("com.secneo.apkwrapper", ignoreCase = true)) {
            evidence.add("manifest: jiagu wrapper")
            confidence += 0.2
        }

        return if (confidence > 0.0) listOf(DetectionResult(
            packerId = "jiagu_generic",
            packerName = "Jiagu (generic)",
            confidence = minOf(1.0, confidence),
            evidence = evidence,
            category = "PACKER",
            extractionMethod = "DYNAMIC",
            requiredTools = listOf("frida-server", "BlackDex"),
        )) else emptyList()
    }

    /**
     * Detects dynamic loading APIs that suggest runtime DEX decryption.
     * Based on research: T05 (ClassLoader Hooking).
     */
    private fun checkDynamicLoading(
        dexTexts: List<String>,
        nativeLibs: List<String>,
    ): List<DetectionResult> {
        val evidence = mutableListOf<String>()
        var confidence = 0.0

        val dynamicApis = listOf(
            "dalvik.system.DexClassLoader",
            "dalvik.system.PathClassLoader",
            "dalvik.system.InMemoryDexClassLoader",
            "dalvik.system.DexFile",
            "java.lang.ClassLoader.loadClass",
            "java.lang.Runtime.load",
            "java.lang.System.loadLibrary",
        )

        for (api in dynamicApis) {
            if (dexTexts.any { it.contains(api, ignoreCase = true) }) {
                evidence.add("dynamic API: $api")
                confidence += 0.1
            }
        }

        // High native lib count suggests packer loading encrypted DEX
        if (nativeLibs.size > 5) {
            evidence.add("high native lib count: ${nativeLibs.size}")
            confidence += 0.1
        }

        return if (confidence > 0.3) listOf(DetectionResult(
            packerId = "dynamic_loading",
            packerName = "Dynamic Loading (suspicious)",
            confidence = minOf(1.0, confidence),
            evidence = evidence,
            category = "SUSPICIOUS",
            extractionMethod = "DYNAMIC",
            requiredTools = listOf("frida-server"),
        )) else emptyList()
    }

    /**
     * Detects DEX encryption patterns (encrypted DEX in assets or appended data).
     * Based on research: T08 (Jiagu DEX Decryption).
     */
    private fun checkDexEncryption(
        dexBuffers: List<ByteArray>,
        entries: List<String>,
    ): List<DetectionResult> {
        val evidence = mutableListOf<String>()
        var confidence = 0.0

        // Check for DEX with suspicious entropy (high byte randomness suggests encryption)
        for ((idx, buffer) in dexBuffers.withIndex()) {
            if (buffer.size > 1024) {
                val entropy = calculateEntropy(buffer)
                if (entropy > 7.5) { // High entropy suggests encryption
                    evidence.add("high entropy in classes${if (idx == 0) "" else idx + 1}.dex: ${String.format("%.2f", entropy)}")
                    confidence += 0.2
                }
            }
        }

        // Check for encrypted DEX in assets
        val suspiciousAssets = entries.filter { entry ->
            entry.contains("assets/") && (
                entry.endsWith(".dat") || entry.endsWith(".bin") ||
                entry.endsWith(".enc") || entry.endsWith(".dex") && !entry.startsWith("classes")
            )
        }
        if (suspiciousAssets.isNotEmpty()) {
            evidence.add("suspicious assets: ${suspiciousAssets.take(3).joinToString()}")
            confidence += 0.2
        }

        return if (confidence > 0.2) listOf(DetectionResult(
            packerId = "encrypted_dex",
            packerName = "Encrypted DEX (suspicious)",
            confidence = minOf(1.0, confidence),
            evidence = evidence,
            category = "SUSPICIOUS",
            extractionMethod = "DYNAMIC",
            requiredTools = listOf("frida-server"),
        )) else emptyList()
    }

    /** Calculates Shannon entropy of a byte array. */
    private fun calculateEntropy(data: ByteArray): Double {
        if (data.isEmpty()) return 0.0
        val freq = IntArray(256)
        for (b in data) freq[b.toInt() and 0xFF]++
        var entropy = 0.0
        val len = data.size.toDouble()
        for (f in freq) {
            if (f > 0) {
                val p = f / len
                entropy -= p * kotlin.math.ln(p) / kotlin.math.ln(2.0)
            }
        }
        return entropy
    }

    private fun toLatin1(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size)
        for (b in bytes) sb.append((b.toInt() and 0xFF).toChar())
        return sb.toString()
    }
}
