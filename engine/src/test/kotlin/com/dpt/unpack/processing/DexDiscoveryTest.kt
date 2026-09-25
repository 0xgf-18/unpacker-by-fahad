package com.dpt.unpack.processing

import com.dpt.unpack.validate.DexValidator
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class DexDiscoveryTest {

    @TempDir
    lateinit var tempDir: Path

    private fun createMinimalDex(name: String): File {
        val dex = ByteArray(112)
        // DEX magic: "dex\n035\0"
        dex[0] = 0x64; dex[1] = 0x65; dex[2] = 0x78; dex[3] = 0x0A
        dex[4] = 0x30; dex[5] = 0x33; dex[6] = 0x35; dex[7] = 0x00
        // file_size at offset 32 = 112
        dex[32] = 0x70; dex[33] = 0x00; dex[34] = 0x00; dex[35] = 0x00
        val file = tempDir.resolve(name).toFile()
        file.writeBytes(dex)
        return file
    }

    private fun createNonDexFile(name: String): File {
        val file = tempDir.resolve(name).toFile()
        file.writeBytes(ByteArray(100) { 0x42 })
        return file
    }

    @Test
    fun `discover finds DEX files by extension`() {
        createMinimalDex("classes.dex")
        createMinimalDex("classes2.dex")
        createNonDexFile("readme.txt")

        val artifacts = DexDiscovery.discover(tempDir.toFile())
        assertEquals(2, artifacts.size)
        assertTrue(artifacts.all { it.type == ArtifactType.DEX })
    }

    @Test
    fun `discoverStandard finds standard DEX naming`() {
        createMinimalDex("classes.dex")
        createMinimalDex("classes2.dex")
        createMinimalDex("classes3.dex")

        val artifacts = DexDiscovery.discoverStandard(tempDir.toFile())
        assertEquals(3, artifacts.size)
        assertEquals("classes.dex", artifacts[0].name)
        assertEquals("classes2.dex", artifacts[1].name)
        assertEquals("classes3.dex", artifacts[2].name)
    }

    @Test
    fun `discoverStandard ignores non-standard names`() {
        createMinimalDex("payload.dex")
        createMinimalDex("classes.dex")

        val artifacts = DexDiscovery.discoverStandard(tempDir.toFile())
        assertEquals(1, artifacts.size)
        assertEquals("classes.dex", artifacts[0].name)
    }

    @Test
    fun `discover rejects non-DEX files with dex extension`() {
        createNonDexFile("fake.dex")
        createMinimalDex("real.dex")

        val artifacts = DexDiscovery.discover(tempDir.toFile())
        assertEquals(1, artifacts.size)
        assertEquals("real.dex", artifacts[0].name)
    }

    @Test
    fun `discover returns empty for non-directory`() {
        val file = tempDir.resolve("not_a_dir.txt").toFile()
        file.writeText("hello")
        val artifacts = DexDiscovery.discover(file)
        assertTrue(artifacts.isEmpty())
    }

    @Test
    fun `isDexBytes validates DEX magic correctly`() {
        val validDex = ByteArray(112)
        validDex[0] = 0x64; validDex[1] = 0x65; validDex[2] = 0x78; validDex[3] = 0x0A
        validDex[4] = 0x30; validDex[5] = 0x33; validDex[6] = 0x35; validDex[7] = 0x00

        assertTrue(DexDiscovery.isDexBytes(validDex))
        assertFalse(DexDiscovery.isDexBytes(ByteArray(8)))
        assertFalse(DexDiscovery.isDexBytes(ByteArray(0)))
    }

    @Test
    fun `dexIndex parses standard names correctly`() {
        assertEquals(1, DexDiscovery.dexIndex("classes.dex"))
        assertEquals(2, DexDiscovery.dexIndex("classes2.dex"))
        assertEquals(10, DexDiscovery.dexIndex("classes10.dex"))
        assertNull(DexDiscovery.dexIndex("payload.dex"))
        assertNull(DexDiscovery.dexIndex("classes.dex.bak"))
    }

    @Test
    fun `validateDex reports errors for invalid DEX`() {
        val file = tempDir.resolve("bad.dex").toFile()
        file.writeBytes(ByteArray(200) { 0x00 })

        val result = DexDiscovery.validateDex(file)
        assertFalse(result.valid)
        assertTrue(result.errors.isNotEmpty())
    }

    @Test
    fun `validateDex reports missing file`() {
        val file = tempDir.resolve("missing.dex").toFile()
        val result = DexDiscovery.validateDex(file)
        assertFalse(result.valid)
        assertTrue(result.errors.any { it.contains("does not exist") })
    }

    @Test
    fun `discover deduplicates files`() {
        createMinimalDex("classes.dex")

        val artifacts = DexDiscovery.discover(tempDir.toFile())
        val uniquePaths = artifacts.map { it.file.absolutePath }.toSet()
        assertEquals(uniquePaths.size, artifacts.size)
    }
}
