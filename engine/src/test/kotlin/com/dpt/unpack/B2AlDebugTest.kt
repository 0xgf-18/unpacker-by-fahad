package com.dpt.unpack

import com.dpt.unpack.b2al.B2AlDetector
import com.dpt.unpack.detection.Profiler
import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals

class B2AlDebugTest {

    private val testApk = File("C:\\Users\\F A H A D\\Desktop\\New folder (3)\\cackme.apk")
    private val b2alCrackme = File("C:\\Users\\F A H A D\\Desktop\\fortest\\b2alcrackme.apk")

    @Test
    fun debugB2AlDetection() {
        listOf(testApk, b2alCrackme).filter { it.exists() }.forEach { apk ->
            println("=== ${apk.name} (${apk.length()} bytes) ===")
            val info = B2AlDetector.detect(apk)
            println("  detected: ${info.detected}")
            println("  carrier: ${info.carrierEntry}")
            println("  records: ${info.records.size}")
            println("  application: ${info.applicationClass}")
            info.reasons.forEach { println("  reason: $it") }
            println()
        }
    }

    @Test
    fun `cackme - full chain recovery validates all 3 DEX records`() {
        if (!testApk.exists()) return
        val info = B2AlDetector.detect(testApk)
        assertTrue(info.detected, "cackme.apk should be detected as B2Al")
        assertEquals(3, info.records.size, "Should recover 3 DEX records")
        for (rec in info.records) {
            assertTrue(rec.data.size >= 0x60, "Record ${rec.index} data too small: ${rec.data.size}")
            assertTrue(rec.data[0] == 0x64.toByte() && rec.data[1] == 0x65.toByte() &&
                rec.data[2] == 0x78.toByte() && rec.data[3] == 0x0A.toByte(),
                "Record ${rec.index} must start with dex magic")
            val fileSize = (rec.data[0x20].toInt() and 0xFF) or
                ((rec.data[0x21].toInt() and 0xFF) shl 8) or
                ((rec.data[0x22].toInt() and 0xFF) shl 16) or
                ((rec.data[0x23].toInt() and 0xFF) shl 24)
            assertEquals(rec.size, fileSize, "Record ${rec.index} file_size mismatch")
            println("  Record ${rec.index}: ${rec.data.size} bytes (sha256=${rec.sha256.take(16)}...)")
        }
        val totalBytes = info.records.sumOf { it.data.size }
        println("  Total recovered: ${info.records.size} DEX files, $totalBytes bytes")
    }

    @Test
    fun `cackme - Profiler routes to static b2al strategy`() {
        if (!testApk.exists()) return
        val profile = Profiler.analyze(testApk)
        val best = Profiler.bestStrategy(profile, Profiler.ownedStrategies())
        println("  bestStrategy for cackme.apk: $best")
        assertEquals("b2al", best, "Profiler should route cackme.apk to static b2al, not b2al_dynamic")
    }

    @Test
    fun debugProfiler() {
        listOf(testApk, b2alCrackme).filter { it.exists() }.forEach { apk ->
            println("=== ${apk.name} ===")
            val profile = Profiler.analyze(apk)
            println("  package: ${profile.packageName}")
            println("  application: ${profile.applicationCls}")
            for (layer in profile.layers) {
                println("  layer: id=${layer.id} name=${layer.name} strategy=${layer.strategy} likelihood=${layer.likelihood}")
                layer.evidence.forEach { e -> println("    evidence: $e") }
            }
            val best = Profiler.bestStrategy(profile, Profiler.ownedStrategies())
            println("  bestStrategy: $best")
            println("  owned: ${Profiler.ownedStrategies()}")
            println()
        }
    }
}
