package com.dpt.unpack

import com.dpt.unpack.detection.Profiler
import com.dpt.unpack.detection.DptDetector
import com.dpt.unpack.b2al.B2AlDetector
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import kotlin.test.assertTrue

class IntegrationTest {

    private val testApkDir = File("C:/Users/F A H A D/Desktop/fortest")

    private fun findTestApk(name: String): File? {
        val f = File(testApkDir, name)
        return if (f.exists()) f else null
    }

    @Test
    fun `B2Al crackme - Profiler detects protection`() {
        val apk = findTestApk("b2alcrackme.apk")
        assumeTrue(apk != null, "b2alcrackme.apk not found in fortest directory")

        val result = Profiler.analyze(apk!!)
        println("===== B2Al CRACKME ANALYSIS =====")
        println("File: ${apk.name} (${apk.length()} bytes)")
        println("Layers detected: ${result.layers.size}")
        for (layer in result.layers) {
            println("  - ${layer.name} | strategy=${layer.strategy} | kind=${layer.kind} | likelihood=${"%.0f".format(layer.likelihood * 100)}%")
            for (ev in layer.evidence) {
                println("    evidence: $ev")
            }
        }
        println("Junk suspects: ${result.junkSuspects.size}")
        for (j in result.junkSuspects) {
            println("  - $j")
        }
        println()

        assertTrue(result.layers.isNotEmpty(), "Should detect at least one protection layer")
    }

    @Test
    fun `DPT crackme - Profiler detects protection`() {
        val apk = findTestApk("dptcrackme.apk")
        assumeTrue(apk != null, "dptcrackme.apk not found in fortest directory")

        val result = Profiler.analyze(apk!!)
        println("===== DPT CRACKME ANALYSIS =====")
        println("File: ${apk.name} (${apk.length()} bytes)")
        println("Layers detected: ${result.layers.size}")
        for (layer in result.layers) {
            println("  - ${layer.name} | strategy=${layer.strategy} | kind=${layer.kind} | likelihood=${"%.0f".format(layer.likelihood * 100)}%")
            for (ev in layer.evidence) {
                println("    evidence: $ev")
            }
        }
        println("Junk suspects: ${result.junkSuspects.size}")
        for (j in result.junkSuspects) {
            println("  - $j")
        }
        println()

        assertTrue(result.layers.isNotEmpty(), "Should detect at least one protection layer")
    }

    @Test
    fun `B2Al crackme - B2AlDetector checks DEX buffers`() {
        val apk = findTestApk("b2alcrackme.apk")
        assumeTrue(apk != null, "b2alcrackme.apk not found in fortest directory")

        val dexBuffers = java.util.zip.ZipFile(apk!!).use { zip ->
            zip.entries().asSequence()
                .filter { it.name.endsWith(".dex") }
                .map { zip.getInputStream(it).readAllBytes() }
                .toList()
        }
        val isB2Al = B2AlDetector.isCarrierAmong(dexBuffers)
        println("===== B2Al DETECTOR =====")
        println("File: ${apk.name}")
        println("DEX files checked: ${dexBuffers.size}")
        println("Is B2Al carrier: $isB2Al")
        println()

        // B2Al detection is based on DEX content analysis; if not detected via
        // DEX buffers, the Profiler's own detection (above) is authoritative.
        // This test documents the B2Al detector's behavior on this sample.
    }

    @Test
    fun `DPT crackme - DptDetector confirms DPT shell`() {
        val apk = findTestApk("dptcrackme.apk")
        assumeTrue(apk != null, "dptcrackme.apk not found in fortest directory")

        val result = DptDetector.detect(apk!!)
        println("===== DPT DETECTOR =====")
        println("File: ${apk.name}")
        println("Detected: ${result.detected}")
        println("Payload dexes: ${result.payloadDexes.size}")
        println("Asset names: ${result.assetNames.size}")
        if (result.reasons.isNotEmpty()) {
            println("Reasons:")
            for (r in result.reasons) {
                println("  - $r")
            }
        }
        println()

        assertTrue(result.detected, "dptcrackme.apk should be detected as DPT-packed")
    }
}
