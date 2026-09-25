package com.dpt.unpack.rebuild

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkValidatorTest {

    @TempDir
    lateinit var tempDir: Path

    @Test
    fun validateMissingFile() {
        val result = ApkValidator.validate(tempDir.resolve("missing.apk").toFile())
        assertFalse(result.structureValid)
        assertTrue(result.errors.any { it.contains("does not exist") })
    }

    @Test
    fun validateEmptyFile() {
        val file = tempDir.resolve("empty.apk").toFile()
        file.writeBytes(ByteArray(0))
        val result = ApkValidator.validate(file)
        assertFalse(result.structureValid)
        assertTrue(result.errors.any { it.contains("empty") })
    }

    @Test
    fun validateValidZipWithDexAndManifest() {
        val apk = createTestApk("valid.apk")
        val result = ApkValidator.validate(apk)
        assertTrue(result.structureValid)
        assertTrue(result.manifestValid)
        assertTrue(result.dexValid)
        assertEquals(1, result.dexEntries.size)
        assertEquals("classes.dex", result.dexEntries[0].name)
    }

    @Test
    fun validateMissingManifest() {
        val file = tempDir.resolve("nomanifest.apk").toFile()
        ZipOutputStream(file.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(createMinimalDexBytes())
            zos.closeEntry()
        }
        val result = ApkValidator.validate(file)
        assertFalse(result.manifestValid)
        assertTrue(result.errors.any { it.contains("AndroidManifest.xml not found") })
    }

    @Test
    fun validateInvalidDex() {
        val file = tempDir.resolve("baddex.apk").toFile()
        ZipOutputStream(file.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(ByteArray(200) { 0x00 })
            zos.closeEntry()
        }
        val result = ApkValidator.validate(file)
        assertFalse(result.dexValid)
        assertTrue(result.errors.any { it.contains("classes.dex") })
    }

    @Test
    fun validateMultiDex() {
        val file = tempDir.resolve("multidex.apk").toFile()
        ZipOutputStream(file.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
            zos.closeEntry()

            for (name in listOf("classes.dex", "classes2.dex", "classes3.dex")) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(createMinimalDexBytes())
                zos.closeEntry()
            }
        }
        val result = ApkValidator.validate(file)
        assertEquals(3, result.dexEntries.size)
        assertTrue(result.dexValid)
    }

    @Test
    fun listDexEntriesWorks() {
        val apk = createTestApk("listtest.apk")
        val dexEntries = ApkValidator.listDexEntries(apk)
        assertEquals(1, dexEntries.size)
        assertEquals("classes.dex", dexEntries[0])
    }

    @Test
    fun hasValidDexWorks() {
        val apk = createTestApk("dextest.apk")
        assertTrue(ApkValidator.hasValidDex(apk))
    }

    @Test
    fun validateDptArtifactsWarning() {
        val file = tempDir.resolve("dpt.apk").toFile()
        ZipOutputStream(file.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(createMinimalDexBytes())
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("assets/OoooooOooo"))
            zos.write(ByteArray(100))
            zos.closeEntry()
        }
        val result = ApkValidator.validate(file)
        assertTrue(result.warnings.any { it.contains("DPT shell artifacts") })
    }

    private fun createTestApk(name: String): File {
        val file = tempDir.resolve(name).toFile()
        ZipOutputStream(file.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(createMinimalDexBytes())
            zos.closeEntry()
        }
        return file
    }

    private fun createMinimalDexBytes(): ByteArray {
        val dex = ByteArray(112)
        dex[0] = 0x64; dex[1] = 0x65; dex[2] = 0x78; dex[3] = 0x0A
        dex[4] = 0x30; dex[5] = 0x33; dex[6] = 0x35; dex[7] = 0x00
        dex[32] = 0x70; dex[33] = 0x00; dex[34] = 0x00; dex[35] = 0x00
        return com.dpt.unpack.checksum.DexChecksum.fix(dex)
    }
}
