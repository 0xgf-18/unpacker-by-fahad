package com.dpt.unpack.rebuild

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class ManifestValidatorTest {

    @TempDir
    lateinit var tempDir: Path

    @Test
    fun validateMissingFile() {
        val result = ManifestValidator.validate(tempDir.resolve("missing.xml").toFile())
        assertFalse(result.valid)
        assertFalse(result.parseable)
        assertTrue(result.errors.any { it.contains("does not exist") })
    }

    @Test
    fun validatePlainXmlManifest() {
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="Test" />
</manifest>"""
        val file = tempDir.resolve("plain.xml").toFile()
        file.writeText(xml)

        val result = ManifestValidator.validate(file)
        assertTrue(result.parseable)
        assertTrue(result.hasPackage)
        assertEquals("com.example.test", result.packageName)
        assertEquals("1.0", result.versionName)
        assertEquals("1", result.versionCode)
    }

    @Test
    fun validatePlainXmlNoPackage() {
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Test" />
</manifest>"""
        val file = tempDir.resolve("nopkg.xml").toFile()
        file.writeText(xml)

        val result = ManifestValidator.validate(file)
        assertTrue(result.parseable)
        assertFalse(result.hasPackage)
        assertTrue(result.warnings.any { it.contains("Package attribute not found") })
    }

    @Test
    fun validateBinaryAxmlMagic() {
        val bytes = byteArrayOf(0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00)
        val result = ManifestValidator.validateBytes(bytes)
        assertTrue(result.parseable)
    }

    @Test
    fun validateTooSmallFile() {
        val file = tempDir.resolve("tiny.xml").toFile()
        file.writeBytes(byteArrayOf(0x01, 0x02))

        val result = ManifestValidator.validate(file)
        assertFalse(result.valid)
        assertTrue(result.errors.any { it.contains("too small") })
    }

    @Test
    fun validateGarbageFile() {
        val file = tempDir.resolve("garbage.xml").toFile()
        file.writeBytes(ByteArray(100) { 0x42 })

        val result = ManifestValidator.validate(file)
        assertFalse(result.parseable)
    }

    @Test
    fun validateFromZipWorks() {
        val file = tempDir.resolve("test.apk").toFile()
        java.util.zip.ZipOutputStream(file.outputStream()).use { zos ->
            zos.putNextEntry(java.util.zip.ZipEntry("AndroidManifest.xml"))
            zos.write("""<?xml version="1.0" encoding="utf-8"?><manifest package="com.test"/>""".toByteArray())
            zos.closeEntry()
        }

        val zipBytes = file.readBytes()
        val result = ManifestValidator.validateFromZip(zipBytes)
        assertTrue(result.parseable)
        assertTrue(result.hasPackage)
        assertEquals("com.test", result.packageName)
    }
}
