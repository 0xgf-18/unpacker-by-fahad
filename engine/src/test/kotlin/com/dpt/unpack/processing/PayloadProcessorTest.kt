package com.dpt.unpack.processing

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class PayloadProcessorTest {

    @TempDir
    lateinit var tempDir: Path

    private fun createMinimalDex(name: String): File {
        val dex = ByteArray(112)
        dex[0] = 0x64; dex[1] = 0x65; dex[2] = 0x78; dex[3] = 0x0A
        dex[4] = 0x30; dex[5] = 0x33; dex[6] = 0x35; dex[7] = 0x00
        dex[32] = 0x70; dex[33] = 0x00; dex[34] = 0x00; dex[35] = 0x00
        val fixed = com.dpt.unpack.checksum.DexChecksum.fix(dex)
        val file = tempDir.resolve(name).toFile()
        file.writeBytes(fixed)
        return file
    }

    @Test
    fun `processAll discovers and processes DEX files`() {
        createMinimalDex("classes.dex")
        createMinimalDex("classes2.dex")

        val processor = PayloadProcessor(tempDir.toFile())
        val result = processor.processAll(source = ArtifactSource.STATIC_ENGINE)

        assertEquals(2, result.totalArtifacts)
        assertEquals(2, result.dexResults.size)
        assertTrue(result.successCount > 0)
    }

    @Test
    fun `processDex validates successfully for valid DEX`() {
        val file = createMinimalDex("valid.dex")
        val artifact = Artifact(
            file = file,
            type = ArtifactType.DEX,
            source = ArtifactSource.STATIC_ENGINE,
            name = "valid.dex",
        )

        val processor = PayloadProcessor(tempDir.toFile())
        val result = processor.processDex(artifact)

        assertEquals(ProcessingStatus.SUCCESS, result.status)
        assertTrue(result.validationErrors.isEmpty())
        assertTrue(result.details.containsKey("classDefsSize"))
    }

    @Test
    fun `processDex fails for invalid DEX`() {
        val file = tempDir.resolve("invalid.dex").toFile()
        file.writeBytes(ByteArray(200) { 0x00 })
        val artifact = Artifact(
            file = file,
            type = ArtifactType.DEX,
            source = ArtifactSource.STATIC_ENGINE,
            name = "invalid.dex",
        )

        val processor = PayloadProcessor(tempDir.toFile())
        val result = processor.processDex(artifact, repairChecksums = false)

        assertEquals(ProcessingStatus.FAILED, result.status)
        assertTrue(result.validationErrors.isNotEmpty())
    }

    @Test
    fun `processDex repairs broken checksum`() {
        val validDex = createMinimalDex("repairable.dex")
        val bytes = validDex.readBytes()
        // Corrupt checksum
        bytes[8] = 0xFF.toByte()
        validDex.writeBytes(bytes)

        val artifact = Artifact(
            file = validDex,
            type = ArtifactType.DEX,
            source = ArtifactSource.STATIC_ENGINE,
            name = "repairable.dex",
        )

        val processor = PayloadProcessor(tempDir.toFile())
        val result = processor.processDex(artifact, repairChecksums = true)

        assertEquals(ProcessingStatus.PARTIAL, result.status)
        assertTrue(result.warnings.any { it.contains("Repaired") })
    }

    @Test
    fun `processMultiDex orders correctly`() {
        val files = listOf(
            createMinimalDex("classes3.dex"),
            createMinimalDex("classes.dex"),
            createMinimalDex("classes2.dex"),
        )

        val processor = PayloadProcessor(tempDir.toFile())
        val results = processor.processMultiDex(files)

        assertEquals(3, results.size)
        assertEquals("classes.dex", results[0].inputArtifact.name)
        assertEquals("classes2.dex", results[1].inputArtifact.name)
        assertEquals("classes3.dex", results[2].inputArtifact.name)
    }

    @Test
    fun `multiDexSummary reports correctly`() {
        createMinimalDex("classes.dex")
        createMinimalDex("classes2.dex")

        val processor = PayloadProcessor(tempDir.toFile())
        processor.processAll()

        val summary = processor.multiDexSummary()
        assertEquals(2, summary.totalDex)
        assertEquals(2, summary.validDex)
        assertTrue(summary.isComplete)
    }

    @Test
    fun `allDexValid returns false when no DEX processed`() {
        val processor = PayloadProcessor(tempDir.toFile())
        assertFalse(processor.allDexValid())
    }

    @Test
    fun `processNonDex classifies correctly`() {
        val file = tempDir.resolve("config.json").toFile()
        file.writeText("""{"key":"value"}""")
        val artifact = Artifact(
            file = file,
            type = ArtifactType.CONFIG,
            source = ArtifactSource.STATIC_ENGINE,
            name = "config.json",
        )

        val processor = PayloadProcessor(tempDir.toFile())
        val result = processor.processNonDex(artifact)

        assertEquals(ProcessingStatus.SUCCESS, result.status)
        assertEquals("CONFIG", result.details["type"])
    }

    @Test
    fun `getResults returns all processed results`() {
        createMinimalDex("a.dex")
        createMinimalDex("b.dex")

        val processor = PayloadProcessor(tempDir.toFile())
        processor.processAll()

        assertEquals(2, processor.getResults().size)
    }

    @Test
    fun `empty workspace produces empty results`() {
        val processor = PayloadProcessor(tempDir.toFile())
        val result = processor.processAll()

        assertEquals(0, result.totalArtifacts)
        assertTrue(result.results.isEmpty())
    }
}
