package com.dpt.unpack.crack

import com.dpt.unpack.axml.AxmlStrings
import com.dpt.unpack.code.CodeRecord
import com.dpt.unpack.crypto.DptCrypto
import com.dpt.unpack.elf.ElfParser
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

data class RecoveredKey(
    val soKeyHex: String,
    val aesKeyHex: String,
    val packageName: String,
    val buildKey: String,
    val configJson: String,
)

/**
 * Result of the analysis-based ("universal") key recovery cascade.
 *
 * [origin] explains how the aes key was resolved:
 *  - "config"  -> the loader's static random key was found and the dpt shell config
 *                 (assets/d_shell_data_001) decrypted with it; aes came from there.
 *  - "derived" -> no static random key found; candidates mined from the loader were
 *                 derived with package/build-key and validated against the code store.
 *  - "symbol"  -> the DPT_UNKNOWN_DATA symbol resolved to real (non-zero) bytes.
 */
data class AnalysisResult(
    val origin: String,
    val soKeyHex: String,
    val aesKeyHex: String,
    val packageName: String,
    val buildKey: String,
    val configJson: String?,
    val prologueHit: Double,
)

object KeyRecovery {

    /** Officially released build keys (shell/build.gradle dptBuildKey / shell-files/build-key). */
    val KNOWN_RELEASE_BUILD_KEYS: List<String> = listOf(
        "e8847a55e441d84",  // v2.21.0
        "778f83cf9a960a01", // v2.20.0 (loader lib2a80863609dc72ed.so -> crackme + GHOST LAG V10)
    )

    /** soName (lib<soName>.so filename) -> released build key, for auto release matching. */
    val SO_NAME_TO_BUILD_KEY: Map<String, String> = mapOf(
        "2a80863609dc72ed" to "778f83cf9a960a01", // v2.20.0
    )

    fun recover(apk: File, extraBuildKeys: List<String>, extraPackageNames: List<String> = emptyList(), debug: Boolean = false): List<RecoveredKey> {
        ZipFile(apk).use { zip ->
            val soBytes = zip.entries().asSequence()
                .filter { !it.isDirectory && it.name.startsWith("assets/") && it.name.endsWith(".so") }
                .mapNotNull { runCatching { zip.getInputStream(it).readAllBytes() }.getOrNull() }
                .firstOrNull()
                ?: throw IllegalStateException("no shell .so under assets/ found in apk")

            val soKey = ElfParser.readSymbolData(soBytes, ElfParser.DPT_UNKNOWN_DATA)
                ?: throw IllegalStateException("DPT_UNKNOWN_DATA symbol not found in shell .so")
            if (soKey.size < 16) throw IllegalStateException("DPT_UNKNOWN_DATA too small: ${soKey.size}")
            // The C symbol is `uint8_t DPT_UNKNOWN_DATA[] = "1234567890abcdef"` (17 bytes).
            // dpt only overwrites the first 16 bytes; the trailing NUL is not part of the key.
            val soKey16 = soKey.copyOf(16)

            val manifestByte = zip.getEntry("AndroidManifest.xml")
                ?: throw IllegalStateException("no AndroidManifest.xml")
            val strings = AxmlStrings.extract(zip.getInputStream(manifestByte).readAllBytes())

            val configEntry = zip.getEntry("assets/d_shell_data_001")
                ?: throw IllegalStateException("no assets/d_shell_data_001")
            val config = zip.getInputStream(configEntry).readAllBytes()

            val pkgCandidates = (packageCandidates(strings) + extraPackageNames).distinct()
            val buildKeys = (KNOWN_RELEASE_BUILD_KEYS + extraBuildKeys).distinct()

            if (debug) {
                println("    [debug] shell .so DPT_UNKNOWN_DATA (soKey) = ${soKey16.joinToString("") { "%02x".format(it) }} (symbol size ${soKey.size})")
                println("    [debug] config size = ${config.size}")
                println("    [debug] manifest strings (first 40): ${strings.take(40)}")
                println("    [debug] package candidates: $pkgCandidates")
                println("    [debug] build-key candidates (${buildKeys.size}): $buildKeys")
            }

            val results = ArrayList<RecoveredKey>()
            // Epoch A (v2.0.0 - v2.15.0): the config is encrypted with the shell .so
            // random key DIRECTLY (AndroidPackage#writeConfig: aesEncrypt(key, genIV(key)))
            // -- no HMAC derivation. Try that first; it is the most precise signal.
            val directPlain = DptCrypto.aesCbcDecrypt(soKey16, DptCrypto.generateIv(soKey16), config)
            if (directPlain != null && looksLikeConfig(directPlain)) {
                val json = directPlain.toString(Charsets.UTF_8)
                results.add(RecoveredKey(soKey16.hex(), soKey16.hex(), "", "", json))
                return results
            }
            // Epoch B (v2.16.0+ build-key): the config is encrypted with
            // HMAC-SHA256(soKey, pkg + "_" + buildKey) -- derive over candidates.
            for (pkg in pkgCandidates) {
                for (bk in buildKeys) {
                    val aesKey = DptCrypto.deriveInsnsKey(soKey16, pkg, bk)
                    val plain = DptCrypto.aesCbcDecrypt(aesKey, DptCrypto.generateIv(soKey16), config) ?: continue
                    if (!looksLikeConfig(plain)) continue
                    val json = plain.toString(Charsets.UTF_8)
                    val aesHex = aesKey.joinToString("") { "%02x".format(it) }
                    results.add(RecoveredKey(soKey16.hex(), aesHex, pkg, bk, json))
                }
            }
            return results
        }
    }

    /**
     * Universal key recovery cascade.
     *
     * Unlike [recover] this makes no assumption about a *named* exported symbol
     * being present, or about the dpt build storing its random key directly.
     * It works for any dpt-shell loader by:
     *
     *  1. harvesting secret candidates from the whole apk: every `assets/**/*.so`
     *     loader (symbol reads + hex/printable strings), the dpt config asset,
     *     and every package name found in the manifest;
     *  2. trying each (randomKey, package, buildKey) combination to derive the
     *     config decryption key. If the dpt config (d_shell_data_001) decrypts,
     *     that combination is correct and the aes key came straight from the
     *     release (most reliable);
     *  3. otherwise deriving candidate aes keys and validating them against the
     *     real code-store records with the dalvik prologue probe, taking the
     *     combination whose decrypted method bodies look like valid dex code.
     */
    fun recoverByAnalysis(
        apk: File,
        recordsForProbe: List<CodeRecord>,
        extraBuildKeys: List<String> = emptyList(),
        pkgHint: String? = null,
        acceptProbe: Double = 0.85,
    ): AnalysisResult? {
        ZipFile(apk).use { zip ->
            val entries = zip.entries().asSequence().filter { !it.isDirectory }.toList()
            val soBytes = entries.filter { it.name.startsWith("assets/") && it.name.endsWith(".so") }.mapNotNull {
                runCatching { zip.getInputStream(it).readAllBytes() }.getOrNull()
            }
            if (soBytes.isEmpty()) soBytes // keep: config-flow may still work

            val configBytes = zip.getEntry("assets/d_shell_data_001")
                ?.let { runCatching { zip.getInputStream(it).readAllBytes() }.getOrNull() }

            val manifestStr = zip.getEntry("AndroidManifest.xml")
                ?.let { runCatching { zip.getInputStream(it).readAllBytes() }.getOrNull() }
                ?.let { runCatching { AxmlStrings.extract(it) }.getOrNull() } ?: emptyList()

            val pkgCandidates = mutableListOf(pkgHint).filterNotNull().toMutableList()
            pkgCandidates.addAll(packageCandidates(manifestStr))
            if (pkgHint != null && pkgHint !in pkgCandidates) pkgCandidates.add(pkgHint)

            val rkStrings = LinkedHashSet<String>()
            val symbolKeys = ArrayList<ByteArray>()
            for (so in soBytes) {
                for (name in listOf("DPT_UNKNOWN_DATA", "dpt_unknown_data", "DPT_RANDOM_KEY", "dpt_random_key", "unknown_data")) {
                    val raw = ElfParser.readSymbolData(so, name)
                    if (raw != null && raw.size in 4..64) symbolKeys.add(raw)
                }
                val txt = String(so, Charsets.ISO_8859_1)
                val hex = Regex("[0-9a-fA-F]{12,60}").findAll(txt)
                for (h in hex) {
                    val v = h.value
                    if (v.length >= 32 || so.size < 500000) rkStrings.add(v)
                }
                // printable windows that could be the per-build random key
                Regex("[\\x20-\\x7e]{24,64}").findAll(txt).forEach {
                    val v = it.value.trim()
                    if (v.length >= 24 && v.all { c -> c.isLetterOrDigit() || c == '_' }) rkStrings.add(v)
                }
            }
            symbolKeys.forEach { rkStrings.add(hexOf(it)) }
            if (rkStrings.isEmpty() && symbolKeys.isEmpty()) rkStrings.add("00000000000000000000000000000000")
            rkStrings.add("00000000000000000000000000000000")
            rkStrings.add("0123456789abcdef")

            val buildKeys = LinkedHashSet<String>()
            buildKeys.addAll(KNOWN_RELEASE_BUILD_KEYS)
            buildKeys.addAll(extraBuildKeys)
            buildKeys.add("")
            for (rk in rkStrings) {
                if (rk.length in 2..17) buildKeys.add(rk)
            }

            // A) config-decrypt prefilter (cheap, high specificity).
            if (configBytes != null) {
                for (rk in rkStrings) {
                    val rkB = rk.let { hexBytesOrLiteral(it) } ?: continue
                    for (pkg in pkgCandidates) {
                        for (bk in buildKeys) {
                            if (bk.isEmpty()) continue
                            val aes = DptCrypto.deriveInsnsKey(rkB, pkg, bk)
                            val iv = DptCrypto.generateIv(rkB)
                            val plain = DptCrypto.aesCbcDecrypt(aes, iv, configBytes) ?: continue
                            if (looksLikeConfig(plain)) {
                                val cfg = String(plain, Charsets.UTF_8)
                                val embedded = Regex("\"AesKey\"\\s*:\\s*\"([0-9a-fA-F]{64})\"").find(cfg)?.groupValues?.get(1)
                                val finalAes = embedded ?: hexOf(aes)
                                val probe = if (recordsForProbe.isNotEmpty()) verifyInsnsByPrologueStats(recordsForProbe, finalAes.let(::hexBytesOrLiteral)!!) else 1.0
                                return AnalysisResult("config", hexOf(rkB), finalAes, pkg, bk, cfg, probe)
                            }
                        }
                    }
                }
            }

            // B) probe-validated derivation over mined candidates.
            if (recordsForProbe.isNotEmpty()) {
                var bestSoFar: Pair<Double, AnalysisResult>? = null
                var candidateCount = 0
                for (rk in rkStrings) {
                    val rkB = rk.let { hexBytesOrLiteral(it) } ?: continue
                    for (pkg in pkgCandidates) {
                        for (bk in buildKeys) {
                            val msg = if (bk.isEmpty()) pkg else "$pkg" + "_" + bk
                            val aesHex = hexOf(DptCrypto.deriveInsnsKey(rkB, pkg, bk))
                            val aesB = hexBytesOrLiteral(aesHex) ?: continue
                            // quick subset probe first to keep it cheap
                            val subset = recordsForProbe.take(24)
                            val quick = verifyInsnsByPrologueStats(subset, aesB)
                            if (quick < acceptProbe * 0.6) continue
                            val full = verifyInsnsByPrologueStats(recordsForProbe, aesB)
                            candidateCount++
                            val cur = AnalysisResult("derived", hexOf(rkB), aesHex, pkg, bk, null, full)
                            if (full >= acceptProbe) return cur
                            if (bestSoFar == null || full > bestSoFar.first) bestSoFar = full to cur
                            if (bestSoFar.first >= 0.5) {
                                return bestSoFar.second
                            }
                        }
                    }
                }
            }
            return null
        }
    }

    private fun hexBytesOrLiteral(s: String): ByteArray? {
        val clean = s.trim().replace(" ", "")
        if (clean.isEmpty() || clean.length % 2 != 0) return null
        if (!clean.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return null
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun hexOf(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    /** Predictable set of valid first-instruction opcodes used as a plaintext sanity probe. */
    private val VALID_FIRST_OPS = setOf(
        0x00, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x1a, 0x22, 0x23, 0x24, 0x60, 0x61, 0x62, 0x6e, 0x6f, 0x70, 0x71,
        0x72, 0x73, 0x74, 0x75, 0x76, 0x78, 0x79, 0x90, 0x92, 0x94, 0x96,
        0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xba, 0xd0, 0xd1, 0xd3, 0xd6, 0xec,
        0xed, 0xe0, 0xe2, 0xf0, 0xf2, 0xea, 0xeb, 0xf8, 0xfa
    )

    /** Sanity-check the derived key by RC4-decrypting code items and probing for valid dalvik. */
    fun verifyInsnsByPrologueStats(records: List<com.dpt.unpack.code.CodeRecord>, aesKey: ByteArray): Double {
        var hits = 0
        var n = 0
        for (rec in records) {
            if (rec.insns.size < 2) continue
            val idx = (rec.methodIdx and 0xFFFFFFFFL).toInt()
            val plain = DptCrypto.rc4(DptCrypto.buildInsnsRc4Key(aesKey, idx), rec.insns)
            val first = plain[0].toInt() and 0xFF
            if (first in VALID_FIRST_OPS) hits++
            n++
        }
        if (n == 0) return 0.0
        return hits.toDouble() / n
    }

    /**
     * Probes the raw (un-decrypted) stored bytes for valid dalvik prologues. When a
     * legacy DPT layout stores method bodies in plaintext (no per-method RC4), the
     * stored instructions already look like valid dex code and this returns a high
     * rate -- signalling that no AES key is required for that code store.
     */
    fun verifyPlaintextPrologueStats(records: List<com.dpt.unpack.code.CodeRecord>): Double {
        var hits = 0
        var n = 0
        for (rec in records) {
            if (rec.insns.size < 2) continue
            val first = rec.insns[0].toInt() and 0xFF
            if (first in VALID_FIRST_OPS) hits++
            n++
        }
        if (n == 0) return 0.0
        return hits.toDouble() / n
    }

    fun parsePackageCandidates(strings: List<String>): List<String> = packageCandidates(strings)

    private fun packageCandidates(strings: List<String>): List<String> {
        val rx = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z0-9_]+)+$")
        val seen = LinkedHashSet<String>()
        strings.filterTo(seen) { it.length in 4..80 && rx.matches(it) }
        return seen.toList()
    }

    private fun looksLikeConfig(plain: ByteArray): Boolean {
        val s = String(plain, Charsets.UTF_8)
        return s.startsWith("{") && (s.contains("app_name") || s.contains("jni_cls_name") ||
            s.contains("dex_sign") || s.contains("risk_check_flags"))
    }
}

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }