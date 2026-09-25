package com.dpt.unpack.processing

import com.dpt.unpack.validate.DexValidator
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class ChecksumRepairTest {

    @TempDir
    lateinit var tempDir: Path

    private fun createMinimalDex(): ByteArray {
        val dex = ByteArray(112)
        dex[0] = 0x64; dex[1] = 0x65; dex[2] = 0x78; dex[3] = 0x0A
        dex[4] = 0x30; dex[5] = 0x33; dex[6] = 0x35; dex[7] = 0x00
        dex[32] = 0x70; dex[33] = 0x00; dex[34] = 0x00; dex[35] = 0x00
        // Fix checksum properly
        return com.dpt.unpack.checksum.DexChecksum.fix(dex)
    }

    @Test
    fun `repairBytes fixes broken checksum`() {
        val validDex = createMinimalDex()
        // Corrupt the checksum
        val corrupted = validDex.copyOf()
        corrupted[8] = 0xFF.toByte()
        corrupted[9] = 0xFF.toByte()
        corrupted[10] = 0xFF.toByte()
        corrupted[11] = 0xFF.toByte()

        // Verify it's now invalid
        assertTrue(DexValidator.validate(corrupted).isNotEmpty())

        val result = ChecksumRepair.repairBytes(corrupted)
        assertTrue(result.isRepaired)
        assertTrue(result.afterErrors.isEmpty())
    }

    @Test
    fun `repairBytes returns same bytes if already valid`() {
        val validDex = createMinimalDex()
        val result = ChecksumRepair.repairBytes(validDex)
        assertFalse(result.isRepaired)
        assertTrue(result.beforeErrors.isEmpty())
        assertTrue(result.afterErrors.isEmpty())
    }

    @Test
    fun `repairInPlace fixes file on disk`() {
        val validDex = createMinimalDex()
        val corrupted = validDex.copyOf()
        corrupted[8] = 0xFF.toByte()

        val file = tempDir.resolve("corrupt.dex").toFile()
        file.writeBytes(corrupted)

        val result = ChecksumRepair.repairInPlace(file)
        assertTrue(result.repaired)
        assertTrue(result.beforeErrors.isNotEmpty())

        // Verify file is now valid on disk
        val onDisk = file.readBytes()
        assertTrue(DexValidator.validate(onDisk).isEmpty())
    }

    @Test
    fun `repairInPlace reports missing file`() {
        val file = tempDir.resolve("missing.dex").toFile()
        val result = ChecksumRepair.repairInPlace(file)
        assertFalse(result.repaired)
        assertTrue(result.beforeErrors.any { it.contains("does not exist") })
    }

    @Test
    fun `repairAll handles multiple files`() {
        val validDex = createMinimalDex()
        val files = (1..3).map { i ->
            val corrupted = validDex.copyOf()
            corrupted[8] = i.toByte()
            val file = tempDir.resolve("dex$i.dex").toFile()
            file.writeBytes(corrupted)
            file
        }

        val results = ChecksumRepair.repairAll(files)
        assertEquals(3, results.size)
        assertTrue(results.all { it.repaired })
    }
}
