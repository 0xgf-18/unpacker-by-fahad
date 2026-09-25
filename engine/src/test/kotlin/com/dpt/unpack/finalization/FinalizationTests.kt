package com.dpt.unpack.finalization

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class SigningConfigTest {

    @TempDir
    lateinit var tempDir: Path

    @Test
    fun configWithMissingKeystoreIsInvalid() {
        val config = SigningConfig.of(
            keystorePath = tempDir.resolve("missing.jks").toFile(),
            storePassword = "pass",
            keyPassword = "pass",
        )
        assertFalse(config.isValid)
    }

    @Test
    fun configWithEmptyPasswordIsInvalid() {
        val ks = tempDir.resolve("test.jks").toFile()
        ks.writeBytes(ByteArray(100))
        val config = SigningConfig.of(ks, "", "")
        assertFalse(config.isValid)
    }

    @Test
    fun configWithValidKeystoreAndPasswordsIsValid() {
        val ks = tempDir.resolve("test.jks").toFile()
        ks.writeBytes(ByteArray(100))
        val config = SigningConfig.of(ks, "password", "password")
        assertTrue(config.isValid)
    }

    @Test
    fun throwawayCreatesConfigWithDefaults() {
        val config = SigningConfig.throwaway(tempDir.toFile())
        assertEquals("dpt-dumper", config.keyAlias)
        assertNotNull(config.storePassword)
        assertNotNull(config.keyPassword)
    }

    @Test
    fun summaryReportsKeystoreStatus() {
        val config = SigningConfig.of(
            keystorePath = tempDir.resolve("test.jks").toFile(),
            storePassword = "pass",
            keyPassword = "pass",
        )
        val summary = config.summary()
        assertTrue(summary.contains("MISSING"))
    }
}

class SignatureValidatorTest {

    @TempDir
    lateinit var tempDir: Path

    @Test
    fun validateMissingFile() {
        val result = SignatureValidator.validate(tempDir.resolve("missing.apk").toFile())
        assertFalse(result.signed)
        assertTrue(result.errors.any { it.contains("does not exist") })
    }

    @Test
    fun validateUnsignedApk() {
        val file = tempDir.resolve("unsigned.apk").toFile()
        ZipOutputStream(file.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(ByteArray(100))
            zos.closeEntry()
        }
        val result = SignatureValidator.validate(file)
        assertFalse(result.signed)
        assertTrue(result.errors.any { it.contains("MANIFEST.MF not found") })
    }

    @Test
    fun validateSignedApk() {
        val file = tempDir.resolve("signed.apk").toFile()
        ZipOutputStream(file.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
            zos.write(ByteArray(50))
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("META-INF/CERT.SF"))
            zos.write(ByteArray(50))
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
            zos.write(ByteArray(50))
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(ByteArray(100))
            zos.closeEntry()
        }
        val result = SignatureValidator.validate(file)
        assertTrue(result.signed)
        assertTrue(result.valid)
        assertEquals(3, result.signatureFiles.size)
    }

    @Test
    fun validateApkWithManifestOnly() {
        val file = tempDir.resolve("manifestonly.apk").toFile()
        ZipOutputStream(file.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
            zos.write(ByteArray(50))
            zos.closeEntry()
        }
        val result = SignatureValidator.validate(file)
        assertFalse(result.signed)
        assertTrue(result.errors.any { it.contains("No signature files") })
    }

    @Test
    fun validateApkWithEmptySignatureFile() {
        val file = tempDir.resolve("emptySig.apk").toFile()
        ZipOutputStream(file.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
            zos.write(ByteArray(50))
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("META-INF/CERT.SF"))
            zos.write(ByteArray(0))
            zos.closeEntry()
        }
        val result = SignatureValidator.validate(file)
        assertTrue(result.warnings.any { it.contains("empty") })
    }
}

class FinalizationResultTest {

    @Test
    fun unknownResultByDefault() {
        val result = FinalizationResult()
        assertEquals(com.dpt.unpack.rebuild.RebuildStatus.UNKNOWN, result.rebuildStatus)
        assertEquals(SigningStatus.UNKNOWN, result.signingStatus)
        assertEquals(InstallStatus.UNKNOWN, result.installStatus)
        assertEquals(LaunchStatus.UNKNOWN, result.launchStatus)
        assertFalse(result.isFullySuccessful)
    }

    @Test
    fun summaryContainsAllStages() {
        val result = FinalizationResult()
        val summary = result.summary
        assertTrue(summary.contains("Rebuild:"))
        assertTrue(summary.contains("Sign:"))
        assertTrue(summary.contains("Install:"))
        assertTrue(summary.contains("Launch:"))
    }

    @Test
    fun detailedReportFormatsCorrectly() {
        val result = FinalizationResult(totalTimeMs = 1000)
        val report = result.detailedReport
        assertTrue(report.contains("FINALIZATION REPORT"))
        assertTrue(report.contains("TOTAL TIME: 1000ms"))
    }
}
