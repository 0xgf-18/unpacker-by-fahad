package com.dpt.unpack

import com.dpt.unpack.checksum.DexChecksum
import com.dpt.unpack.processing.*
import com.dpt.unpack.rebuild.ApkRebuilder
import com.dpt.unpack.validate.DexValidator
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class PerformanceBenchmarkTest {

    @TempDir
    lateinit var tempDir: Path

    private fun createMinimalDexBytes(): ByteArray {
        val dex = ByteArray(112)
        dex[0] = 0x64; dex[1] = 0x65; dex[2] = 0x78; dex[3] = 0x0A
        dex[4] = 0x30; dex[5] = 0x33; dex[6] = 0x35; dex[7] = 0x00
        dex[32] = 0x70; dex[33] = 0x00; dex[34] = 0x00; dex[35] = 0x00
        return DexChecksum.fix(dex)
    }

    private fun createMinimalManifestBytes(): ByteArray {
        return """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app">
    <application android:label="Test"/>
</manifest>""".toByteArray()
    }

    private fun createMinimalApk(name: String): File {
        val apk = tempDir.resolve(name).toFile()
        ZipOutputStream(apk.outputStream()).use { zos ->
            val manifestEntry = ZipEntry("AndroidManifest.xml")
            manifestEntry.method = ZipEntry.DEFLATED
            zos.putNextEntry(manifestEntry)
            zos.write(createMinimalManifestBytes())
            zos.closeEntry()

            val dexEntry = ZipEntry("classes.dex")
            dexEntry.method = ZipEntry.DEFLATED
            zos.putNextEntry(dexEntry)
            zos.write(createMinimalDexBytes())
            zos.closeEntry()
        }
        return apk
    }

    // --- Benchmark 4: APK Analysis ---
    @Test
    fun `benchmark APK analysis - DexDiscovery PayloadDiscovery DexValidator`() {
        val iterations = 3
        val dexTimes = mutableListOf<Double>()
        val payloadTimes = mutableListOf<Double>()
        val validateTimes = mutableListOf<Double>()

        repeat(iterations) { run ->
            val workDir = tempDir.resolve("bench_run_$run").toFile()
            workDir.mkdirs()
            val dex = createMinimalDexBytes()
            workDir.resolve("classes.dex").writeBytes(dex)
            workDir.resolve("classes2.dex").writeBytes(dex)
            workDir.resolve("AndroidManifest.xml").writeBytes(createMinimalManifestBytes())
            workDir.resolve("config.json").writeBytes("""{"key":"value"}""".toByteArray())

            // DexDiscovery
            val t1 = System.nanoTime()
            DexDiscovery.discover(workDir)
            dexTimes.add((System.nanoTime() - t1) / 1_000_000.0)

            // PayloadDiscovery
            val t2 = System.nanoTime()
            PayloadDiscovery.discover(workDir)
            payloadTimes.add((System.nanoTime() - t2) / 1_000_000.0)

            // DexValidator
            val dexBytes = workDir.resolve("classes.dex").readBytes()
            val t3 = System.nanoTime()
            DexValidator.validate(dexBytes)
            validateTimes.add((System.nanoTime() - t3) / 1_000_000.0)

            workDir.deleteRecursively()
        }

        val avgDex = dexTimes.average()
        val avgPayload = payloadTimes.average()
        val avgValidate = validateTimes.average()

        println("===== BENCHMARK 4: APK ANALYSIS =====")
        println("DexDiscovery.discover():       avg=${"%.3f".format(avgDex)}ms  (runs: ${dexTimes.map { "%.3f".format(it) }})")
        println("PayloadDiscovery.discover():   avg=${"%.3f".format(avgPayload)}ms  (runs: ${payloadTimes.map { "%.3f".format(it) }})")
        println("DexValidator.validate():       avg=${"%.3f".format(avgValidate)}ms  (runs: ${validateTimes.map { "%.3f".format(it) }})")
        println()
    }

    // --- Benchmark 5: DEX Processing ---
    @Test
    fun `benchmark DEX processing - PayloadProcessor with 10 DEX files`() {
        val iterations = 3
        val processTimes = mutableListOf<Double>()

        repeat(iterations) { run ->
            val workDir = tempDir.resolve("proc_run_$run").toFile()
            workDir.mkdirs()
            val dex = createMinimalDexBytes()
            for (i in 1..10) {
                val name = if (i == 1) "classes.dex" else "classes$i.dex"
                workDir.resolve(name).writeBytes(dex)
            }

            val t = System.nanoTime()
            val processor = PayloadProcessor(workDir)
            processor.processAll(source = ArtifactSource.STATIC_ENGINE)
            processTimes.add((System.nanoTime() - t) / 1_000_000.0)

            workDir.resolve("processed")?.deleteRecursively()
            workDir.deleteRecursively()
        }

        val avg = processTimes.average()
        println("===== BENCHMARK 5: DEX PROCESSING (10 files) =====")
        println("PayloadProcessor.processAll(): avg=${"%.3f".format(avg)}ms  (runs: ${processTimes.map { "%.3f".format(it) }})")
        println()
    }

    // --- Benchmark 6: APK Rebuild ---
    @Test
    fun `benchmark APK rebuild - ApkRebuilder`() {
        val iterations = 3
        val rebuildTimes = mutableListOf<Double>()

        repeat(iterations) { run ->
            val workDir = tempDir.resolve("rebuild_run_$run").toFile()
            workDir.mkdirs()

            // Create input APK
            val inputApk = workDir.resolve("input.apk")
            ZipOutputStream(inputApk.outputStream()).use { zos ->
                val manifestEntry = ZipEntry("AndroidManifest.xml")
                manifestEntry.method = ZipEntry.DEFLATED
                zos.putNextEntry(manifestEntry)
                zos.write(createMinimalManifestBytes())
                zos.closeEntry()

                val dexEntry = ZipEntry("classes.dex")
                dexEntry.method = ZipEntry.DEFLATED
                zos.putNextEntry(dexEntry)
                zos.write(createMinimalDexBytes())
                zos.closeEntry()

                val resEntry = ZipEntry("resources.arsc")
                resEntry.method = ZipEntry.DEFLATED
                zos.putNextEntry(resEntry)
                zos.write(ByteArray(100))
                zos.closeEntry()
            }

            // Create patched dir with restored DEX
            val patchedDir = workDir.resolve("patched")
            patchedDir.mkdirs()
            patchedDir.resolve("classes.dex").writeBytes(createMinimalDexBytes())

            val outApk = workDir.resolve("rebuilt.apk")

            val t = System.nanoTime()
            ApkRebuilder.rebuild(inputApk, patchedDir, createMinimalManifestBytes(), outApk)
            rebuildTimes.add((System.nanoTime() - t) / 1_000_000.0)

            workDir.deleteRecursively()
        }

        val avg = rebuildTimes.average()
        println("===== BENCHMARK 6: APK REBUILD =====")
        println("ApkRebuilder.rebuild():       avg=${"%.3f".format(avg)}ms  (runs: ${rebuildTimes.map { "%.3f".format(it) }})")
        println()
    }
}
