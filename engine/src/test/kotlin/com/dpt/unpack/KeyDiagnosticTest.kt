package com.dpt.unpack

import com.dpt.unpack.code.OoooooOoooParser
import com.dpt.unpack.crack.KeyRecovery
import com.dpt.unpack.detection.DptDetector
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import kotlin.test.assertTrue

class KeyDiagnosticTest {

    private val apk = File("C:/Users/F A H A D/Desktop/fortest/dptcrackme.apk")

    @Test
    fun `diagnose code store encryption and recover key`() {
        assumeTrue(apk.exists(), "dptcrackme.apk not found")
        val det = DptDetector.detect(apk)
        assertTrue(det.detected, "should detect DPT")

        val codeAsset = det.codeAsset!!
        val cands = OoooooOoooParser.parseCandidates(codeAsset)
        println("===== KEY DIAGNOSTIC (dptcrackme.apk) =====")
        println("payload dexes: ${det.payloadDexes.size}")
        println("candidates: ${cands.size}")

        val allRecsByLayout = cands.map { c ->
            c.sections.entries.sortedBy { it.key }.flatMap { (dexIndex, recs) ->
                recs.map { it }
            }
        }

        cands.forEachIndexed { i, c ->
            val recs = c.sections.values.flatten()
            val plain = KeyRecovery.verifyPlaintextPrologueStats(recs)
            val rawMarkers = recs.count { it.insns.isNotEmpty() }
            println("cand[$i] ${c.layoutDesc} records=${rawMarkers} plaintextScore=${"%.2f".format(plain)}")
        }

        val best = allRecsByLayout.maxBy { recs ->
            recs.count { r -> r.insns.isNotEmpty() }
        }
        println("probe records for key recovery: ${best.size}")

        try {
            val res = KeyRecovery.recoverByAnalysis(
                apk, best,
                pkgHint = "com.Nipex.laa",
                acceptProbe = 0.5,
            )
            if (res != null) {
                println("RECOVERED: origin=${res.origin}")
                println("  soKey=${res.soKeyHex}")
                println("  aesKey=${res.aesKeyHex}")
                println("  pkg=${res.packageName} buildKey=${res.buildKey}")
                println("  prologueHit=${"%.2f".format(res.prologueHit)}")
                println("  configJson=${res.configJson?.take(200)}...")
            } else {
                println("NO KEY RECOVERED")
            }
        } catch (e: Exception) {
            println("key recovery threw: ${e.message}")
            e.printStackTrace()
        }
    }

    @Test
    fun `full pipeline restore + rebuild + sign`() {
        assumeTrue(apk.exists(), "dptcrackme.apk not found")
        val det = DptDetector.detect(apk)
        assertTrue(det.detected, "should detect DPT")

        val codeAsset = det.codeAsset!!
        val cands = OoooooOoooParser.parseCandidates(codeAsset)
        assertTrue(cands.isNotEmpty())
        val b = cands.maxBy { c ->
            c.sections.values.flatten().count { r ->
                r.insns.size == det.payloadDexes.getOrNull(c.sections.keys.firstOrNull() ?: 0)?.bytes?.size
            }
        }
        println("===== FULL PIPELINE (dptcrackme.apk) =====")
        println("layout: ${b.layoutDesc}")

        val probeRecords = b.sections.values.flatten()
        val plainScore = KeyRecovery.verifyPlaintextPrologueStats(probeRecords)
        var aesKey: ByteArray? = null
        if (plainScore < 0.5) {
            println("encrypted code store (plainScore=${"%.2f".format(plainScore)}), recovering key...")
            val rec = KeyRecovery.recoverByAnalysis(apk, probeRecords, pkgHint = "com.Nipex.laa")
            if (rec != null) {
                val aes = rec.aesKeyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val hit = KeyRecovery.verifyInsnsByPrologueStats(probeRecords, aes)
                println("aesKey=${rec.aesKeyHex} origin=${rec.origin} hit=${"%.2f".format(hit)}")
                if (hit >= 0.4) aesKey = aes
            }
        }

        // restore each dex
        val outDir = java.io.File("C:/Users/F A H A D/Desktop/Universal Tool/DPT-UNPACKER/engine/build/pipeline_out")
        outDir.deleteRecursively(); outDir.mkdirs()
        val pd = java.io.File(outDir, "patched_dex").apply { mkdirs() }
        b.sections.forEach { (di, recs) ->
            val dex = det.payloadDexes.getOrNull(di) ?: return@forEach
            val r = com.dpt.unpack.restore.DexRestorer.restore(dex.bytes, recs, aesKey = aesKey, label = "cls$di")
            val name = if (di == 0) "classes.dex" else "classes${di + 1}.dex"
            java.io.File(pd, name).writeBytes(r.dex)
            println("  $name: patched=${r.patched} skips=${r.skipped} mm=${r.mismatches} hooks=${r.hooksNeutralized}")
        }

        val mb = java.util.zip.ZipFile(apk).use { z ->
            z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes()
        }
        val pdf = pd.listFiles { f, n -> n.startsWith("classes") && n.endsWith(".dex") }!!.sortedBy {
            if (it.name == "classes.dex") 0 else it.name.removePrefix("classes").removeSuffix(".dex").toInt()
        }.map { it.readBytes() }
        val ra = com.dpt.unpack.ark.ArkDexTools.discoverRealApplication(null, pdf, null)
        var pm = if (ra != null) {
            println("  real application: $ra")
            com.dpt.unpack.axml.AxmlManifest.setApplicationName(mb, ra)
        } else com.dpt.unpack.axml.AxmlManifest.restoreApplication(mb)
        pm = com.dpt.unpack.axml.AxmlManifest.removeAttribute(pm, "application", "appComponentFactory")

        val unsigned = java.io.File(outDir, "unsigned.apk")
        com.dpt.unpack.rebuild.ApkRebuilder.rebuild(apk, pd, pm, unsigned)

        val signed = java.io.File(outDir, "dptcrackme-unpacked.apk")
        val cfg = com.dpt.unpack.finalization.SigningConfig(
            keystorePath = java.io.File("C:/Users/F A H A D/Desktop/Universal Tool/DPT-UNPACKER/android-app/src/main/assets/appkey.p12"),
            storePassword = "dptunpack",
            keyPassword = "dptunpack",
            keyAlias = "dpt",
            buildToolsDir = java.io.File("C:/Users/F A H A D/AppData/Local/Android/Sdk/build-tools/35.0.0"),
        )
        val sig = com.dpt.unpack.finalization.ApkSigner.sign(cfg, unsigned, signed)
        println("  signing: ${sig.status} ${sig.details}")
        unsigned.delete()

        val v = com.dpt.unpack.capability.ExtractionValidator.validateApk(signed)
        println("  validation: ${if (v.valid) "PASS" else "FAIL: ${v.issues}"}")
        println("  out: ${signed.absolutePath} (${signed.length()} bytes)")
        assertTrue(signed.exists(), "signed output must exist")
    }
}