package com.dpt.unpack.processing

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class PayloadDiscoveryTest {

    @TempDir
    lateinit var tempDir: Path

    private fun createMinimalDex(name: String): File {
        val dex = ByteArray(112)
        dex[0] = 0x64; dex[1] = 0x65; dex[2] = 0x78; dex[3] = 0x0A
        dex[4] = 0x30; dex[5] = 0x33; dex[6] = 0x35; dex[7] = 0x00
        dex[32] = 0x70; dex[33] = 0x00; dex[34] = 0x00; dex[35] = 0x00
        val file = tempDir.resolve(name).toFile()
        file.writeBytes(dex)
        return file
    }

    private fun createElfFile(name: String): File {
        val elf = ByteArray(64)
        elf[0] = 0x7F; elf[1] = 0x45; elf[2] = 0x4C; elf[3] = 0x46 // ELF magic
        elf[4] = 0x02 // 64-bit
        val file = tempDir.resolve(name).toFile()
        file.writeBytes(elf)
        return file
    }

    private fun createJsonFile(name: String): File {
        val file = tempDir.resolve(name).toFile()
        file.writeText("""{"key": "value"}""")
        return file
    }

    @Test
    fun `classifyFile identifies DEX files`() {
        val file = createMinimalDex("test.dex")
        val artifact = PayloadDiscovery.classifyFile(file, tempDir.toFile(), ArtifactSource.STATIC_ENGINE)
        assertNotNull(artifact)
        assertEquals(ArtifactType.DEX, artifact!!.type)
    }

    @Test
    fun `classifyFile identifies native libraries`() {
        val file = createElfFile("libtest.so")
        val artifact = PayloadDiscovery.classifyFile(file, tempDir.toFile(), ArtifactSource.STATIC_ENGINE)
        assertNotNull(artifact)
        assertEquals(ArtifactType.NATIVE_LIB, artifact!!.type)
    }

    @Test
    fun `classifyFile identifies config files`() {
        val file = createJsonFile("config.json")
        val artifact = PayloadDiscovery.classifyFile(file, tempDir.toFile(), ArtifactSource.STATIC_ENGINE)
        assertNotNull(artifact)
        assertEquals(ArtifactType.CONFIG, artifact!!.type)
    }

    @Test
    fun `classifyFile rejects empty files`() {
        val file = tempDir.resolve("empty.txt").toFile()
        file.writeBytes(ByteArray(0))
        val artifact = PayloadDiscovery.classifyFile(file, tempDir.toFile(), ArtifactSource.STATIC_ENGINE)
        assertNull(artifact)
    }

    @Test
    fun `discover finds mixed artifact types`() {
        createMinimalDex("classes.dex")
        createElfFile("libnative.so")
        createJsonFile("config.json")

        val artifacts = PayloadDiscovery.discover(tempDir.toFile())
        assertEquals(3, artifacts.size)

        val types = artifacts.map { it.type }.toSet()
        assertTrue(types.contains(ArtifactType.DEX))
        assertTrue(types.contains(ArtifactType.NATIVE_LIB))
        assertTrue(types.contains(ArtifactType.CONFIG))
    }

    @Test
    fun `discoverOutput only searches output directory`() {
        // Create files in input and output dirs
        val inputDir = tempDir.resolve("input").toFile().also { it.mkdirs() }
        val outputDir = tempDir.resolve("output").toFile().also { it.mkdirs() }

        createMinimalDexIn(inputDir, "input.dex")
        createMinimalDexIn(outputDir, "output.dex")

        val artifacts = PayloadDiscovery.discoverOutput(tempDir.toFile())
        assertEquals(1, artifacts.size)
        assertEquals("output.dex", artifacts[0].name)
    }

    @Test
    fun `summarize produces correct counts`() {
        createMinimalDex("classes.dex")
        createMinimalDex("classes2.dex")
        createElfFile("lib.so")

        val artifacts = PayloadDiscovery.discover(tempDir.toFile())
        val summary = PayloadDiscovery.summarize(artifacts)

        assertEquals(3, summary.totalArtifacts)
        assertEquals(2, summary.dexCount)
        assertEquals(1, summary.nativeLibCount)
    }

    @Test
    fun `dexArtifacts filters correctly`() {
        createMinimalDex("classes.dex")
        createElfFile("lib.so")
        createJsonFile("config.json")

        val artifacts = PayloadDiscovery.discover(tempDir.toFile())
        val dexOnly = PayloadDiscovery.dexArtifacts(artifacts)
        assertEquals(1, dexOnly.size)
        assertEquals(ArtifactType.DEX, dexOnly[0].type)
    }

    @Test
    fun `bySource filters correctly`() {
        val file1 = createMinimalDex("a.dex")
        val file2 = createMinimalDex("b.dex")

        val a1 = PayloadDiscovery.classifyFile(file1, tempDir.toFile(), ArtifactSource.STATIC_ENGINE)!!
        val a2 = PayloadDiscovery.classifyFile(file2, tempDir.toFile(), ArtifactSource.DYNAMIC_ENGINE)!!
        val artifacts = listOf(a1, a2)

        assertEquals(1, PayloadDiscovery.bySource(artifacts, ArtifactSource.STATIC_ENGINE).size)
        assertEquals(1, PayloadDiscovery.bySource(artifacts, ArtifactSource.DYNAMIC_ENGINE).size)
        assertEquals(0, PayloadDiscovery.bySource(artifacts, ArtifactSource.MANUAL).size)
    }

    private fun createMinimalDexIn(dir: File, name: String): File {
        val dex = ByteArray(112)
        dex[0] = 0x64; dex[1] = 0x65; dex[2] = 0x78; dex[3] = 0x0A
        dex[4] = 0x30; dex[5] = 0x33; dex[6] = 0x35; dex[7] = 0x00
        dex[32] = 0x70; dex[33] = 0x00; dex[34] = 0x00; dex[35] = 0x00
        val file = dir.resolve(name)
        file.writeBytes(dex)
        return file
    }
}
