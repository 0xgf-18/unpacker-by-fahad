package com.dpt.unpack.app

import com.dpt.unpack.ark.ArkDexTools
import com.dpt.unpack.axml.AxmlManifest
import com.dpt.unpack.capability.ExtractionValidator
import com.dpt.unpack.code.OoooooOoooParser
import com.dpt.unpack.detection.DptDetector
import com.dpt.unpack.restore.DexRestorer
import com.android.apksig.ApkSigner
import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

object UnpackOrchestrator {

    data class UnpackResult(
        val strategy: String,
        val finalApk: File,
        val outDir: File,
        val log: List<String>,
        val elapsed: Long,
        val validation: ExtractionValidator.ValidationResult? = null,
    )

    private const val KEY_ALIAS = "dpt"
    private const val KEY_STORE_PASS = "dptunpack"

    fun unpack(apk: File, outDir: File, strategy: String, keystore: File, log: (String) -> Unit, outputBaseName: String? = null): UnpackResult {
        val start = System.currentTimeMillis()
        outDir.deleteRecursively()
        outDir.mkdirs()
        return when (strategy) {
            "dpt" -> unpackDpt(apk, outDir, keystore, log, start, outputBaseName)
            else -> throw IllegalArgumentException("unsupported strategy: $strategy")
        }
    }

    private fun unpackDpt(apk: File, outDir: File, keystore: File, log: (String) -> Unit, start: Long, outputBaseName: String?): UnpackResult {
        val L = mutableListOf<String>(); fun e(s: String) { log(s); L.add(s) }
        e("[1/4] Detecting DPT Shell payload...")
        val det = DptDetector.detect(apk)
        if (!det.detected) throw IllegalStateException("not a DPT-packed APK")
        e("  payload dexes: ${det.payloadDexes.size}")
        e("[2/4] Recovering code records...")
        val codeAsset = det.codeAsset ?: throw IllegalStateException("missing OoooooOooo code asset")
        val cands = OoooooOoooParser.parseCandidates(codeAsset)
        if (cands.isEmpty()) throw IllegalStateException("no code store candidates found")
        val caps = det.payloadDexes.map { com.dpt.unpack.dex.DexParser.parseMethods(it.bytes).associate { m -> m.methodIdx to m.insnsByteSize } }
        val best = pickBest(cands, det.payloadDexes, caps)
        val b = cands[best.idx]; e("  layout: ${b.layoutDesc} (score=${"%.2f".format(best.score)})")
        val probeRecords = b.sections.values.flatten()
        val plainScore = com.dpt.unpack.crack.KeyRecovery.verifyPlaintextPrologueStats(probeRecords)
        var aesKey: ByteArray? = null
        if (plainScore < 0.5) {
            e("  code store encrypted (plaintext hit=${"%.2f".format(plainScore)}) — recovering key...")
            val rec = try {
                com.dpt.unpack.crack.KeyRecovery.recoverByAnalysis(apk, probeRecords, pkgHint = packageNameOf(apk))
            } catch (ex: Exception) {
                e("  key recovery error: ${ex.message}")
                null
            }
            if (rec != null) {
                val aes = hexToBytes(rec.aesKeyHex)
                val hit = com.dpt.unpack.crack.KeyRecovery.verifyInsnsByPrologueStats(probeRecords, aes)
                e("  aesKey=${rec.aesKeyHex} origin=${rec.origin} hit=${"%.2f".format(hit)}")
                if (hit >= 0.4) aesKey = aes else e("  key rejected (low hit)")
            } else {
                e("  no key recovered; restoring raw bodies")
            }
        }
        e("[3/4] Restoring dex bodies...")
        val pd = File(outDir, "patched_dex").apply { deleteRecursively(); mkdirs() }
        for (di in b.sections.keys.sorted()) {
            val recs = b.sections[di]!!; val dex = det.payloadDexes.getOrNull(di) ?: continue
            val r = if (aesKey != null) DexRestorer.restore(dex.bytes, recs, aesKey = aesKey, label = "cls$di")
            else DexRestorer.restore(dex.bytes, recs, label = "cls$di")
            r.dex.writeTo(File(pd, r.nameFor(di)))
            e("  ${r.nameFor(di)}: patched=${r.patched} hooks=${r.hooksNeutralized}" + if (r.skipped > 0) " skipped=${r.skipped}" else "" + if (r.mismatches > 0) " mismatches=${r.mismatches}" else "")
        }
        e("[4/4] Rebuilding APK...")
        val mb = ZipFile(apk).use { z -> z.getEntry("AndroidManifest.xml")?.let { z.getInputStream(it).readBytes() } } ?: throw IllegalStateException("no AndroidManifest.xml")
        val pdf = pd.listFiles { f, n -> n.startsWith("classes") && n.endsWith(".dex") }?.sortedBy { if (it.name == "classes.dex") 0 else it.name.removePrefix("classes").removeSuffix(".dex").toInt() }?.map { it.readBytes() } ?: emptyList()
        val ra = ArkDexTools.discoverRealApplication(null, pdf, null)
        var pm = if (ra != null) { e("  application: $ra"); AxmlManifest.setApplicationName(mb, ra) } else AxmlManifest.restoreApplication(mb)
        pm = AxmlManifest.removeAttribute(pm, "application", "appComponentFactory")
        val u = File(outDir, "unsigned.apk"); com.dpt.unpack.rebuild.ApkRebuilder.rebuild(apk, pd, pm, u)
        val fa = File(outDir, (outputBaseName ?: (apk.nameWithoutExtension + "-unpacked")) + ".apk"); signApk(u, fa, keystore); u.delete()
        if (!fa.isFile) throw IllegalStateException("output APK missing")
        val v = ExtractionValidator.validateApk(fa); e("  validation: ${if (v.valid) "PASS" else "FAIL: " + v.issues.joinToString()}")
        e("  done: ${fa.name} (${fa.length()} bytes)"); return UnpackResult("dpt", fa, outDir, L, System.currentTimeMillis() - start, v)
    }

    private fun signApk(input: File, output: File, keystore: File) {
        try {
            val ks = KeyStore.getInstance("PKCS12").apply { load(keystore.inputStream(), KEY_STORE_PASS.toCharArray()) }
            val chain = ks.getCertificateChain(KEY_ALIAS).map { it as X509Certificate }
            val key = ks.getKey(KEY_ALIAS, KEY_STORE_PASS.toCharArray()) as PrivateKey
            val cfg = ApkSigner.SignerConfig.Builder(KEY_ALIAS, key, chain).build()
            ApkSigner.Builder(listOf(cfg)).setInputApk(input).setOutputApk(output).setV1SigningEnabled(true).setV2SigningEnabled(true).build().sign()
        } catch (e: Exception) {
            throw IllegalStateException("APK signing failed: ${e.message}", e)
        }
    }

    private fun pickBest(candidates: List<com.dpt.unpack.code.CodeStoreCandidate>, payloadDexes: List<com.dpt.unpack.detection.PayloadDex>, capacitiesByDex: List<Map<Long, Int>>): CandidateScore {
        return candidates.mapIndexed { idx, cand ->
            var score = 0.0; var matched = 0; var total = 0
            for ((dexIndex, records) in cand.sections) {
                val caps = capacitiesByDex.getOrNull(dexIndex)
                for (rec in records) { total++; val cap = caps?.get(rec.methodIdx); when { cap == null -> score -= 0.5; rec.insns.size == cap -> { score += 1.0; matched++ }; rec.insns.size > cap -> score -= 2.0; else -> score -= 0.25 } }
            }
            CandidateScore(idx, cand.layoutDesc, score, matched, total)
        }.maxByOrNull { it.score } ?: throw IllegalStateException("no candidates")
    }

    data class CandidateScore(val idx: Int, val layoutDesc: String, val score: Double, val matched: Int, val total: Int)

    private fun ByteArray.writeTo(file: File) { file.writeBytes(this) }
    private fun com.dpt.unpack.restore.RestoreResult.nameFor(dexIndex: Int): String =
        if (dexIndex == 0) "classes.dex" else "classes${dexIndex + 1}.dex"

    private fun hexToBytes(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun packageNameOf(apk: File): String? {
        return try {
            java.util.zip.ZipFile(apk).use { z ->
                val mb = z.getEntry("AndroidManifest.xml")?.let { z.getInputStream(it).readBytes() } ?: return null
                val rx = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z0-9_]+)+$")
                com.dpt.unpack.axml.AxmlStrings.extract(mb).firstOrNull { rx.matches(it) }
            }
        } catch (e: Exception) {
            null
        }
    }
}