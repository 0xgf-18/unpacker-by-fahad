package com.dpt.unpack.rebuild

import com.dpt.unpack.validate.DexValidator
import java.io.File
import java.util.zip.ZipFile

/**
 * Validates a rebuilt APK's ZIP structure and contents.
 *
 * Checks:
 * - Valid ZIP/APK structure
 * - Readable entries
 * - No unexpected corruption
 * - Required files exist (AndroidManifest.xml)
 * - DEX files are valid
 * - Expected payloads are present
 * - No DPT shell artifacts remain
 */
object ApkValidator {

    private val DEX_NAME = Regex("classes\\d*\\.dex")

    /**
     * Validate an APK file.
     *
     * @param apkFile the APK to validate
     * @return validation result
     */
    fun validate(apkFile: File): ApkValidationResult {
        if (!apkFile.exists()) {
            return ApkValidationResult(
                structureValid = false,
                manifestValid = false,
                dexValid = false,
                errors = listOf("APK file does not exist"),
            )
        }

        if (apkFile.length() == 0L) {
            return ApkValidationResult(
                structureValid = false,
                manifestValid = false,
                dexValid = false,
                errors = listOf("APK file is empty"),
            )
        }

        return try {
            validateZip(apkFile)
        } catch (e: Exception) {
            ApkValidationResult(
                structureValid = false,
                manifestValid = false,
                dexValid = false,
                errors = listOf("Failed to open APK: ${e.message}"),
            )
        }
    }

    /**
     * Validate APK bytes directly.
     */
    fun validateBytes(apkBytes: ByteArray): ApkValidationResult {
        val tempFile = File.createTempFile("apk-validate", ".apk")
        return try {
            tempFile.writeBytes(apkBytes)
            validateZip(tempFile)
        } finally {
            tempFile.delete()
        }
    }

    /**
     * Validate APK from a ZipFile.
     */
    private fun validateZip(apkFile: File): ApkValidationResult {
        val entries = mutableListOf<ApkEntry>()
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        var hasManifest = false
        var dexCount = 0
        var nativeLibCount = 0
        var dexValid = true
        var totalSize = 0L

        ZipFile(apkFile).use { zip ->
            val zipEntries = zip.entries()
            while (zipEntries.hasMoreElements()) {
                val entry = zipEntries.nextElement()
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                totalSize += entry.size

                val apkEntry = ApkEntry(
                    name = entry.name,
                    size = entry.size,
                    compressedSize = entry.compressedSize,
                    method = entry.method,
                    crc = entry.crc,
                )
                entries.add(apkEntry)

                when {
                    entry.name == "AndroidManifest.xml" -> hasManifest = true
                    entry.name.matches(DEX_NAME) -> {
                        dexCount++
                        val dexErrors = DexValidator.validate(bytes)
                        if (dexErrors.isNotEmpty()) {
                            dexValid = false
                            errors.add("DEX ${entry.name}: ${dexErrors.joinToString("; ")}")
                        }
                    }
                    entry.name.startsWith("lib/") && entry.name.endsWith(".so") -> {
                        nativeLibCount++
                    }
                }
            }
        }

        if (!hasManifest) {
            errors.add("AndroidManifest.xml not found")
        }

        // Check for DPT shell artifacts that should have been removed
        val dptArtifacts = entries.filter {
            it.name == "assets/OoooooOooo" ||
                it.name == "assets/d_shell_data_001" ||
                it.name.startsWith("assets/vwwwwwvwww") ||
                it.name.startsWith("assets/OOooooOooo") ||
                it.name == "assets/OooooOOooo"
        }
        if (dptArtifacts.isNotEmpty()) {
            warnings.add("DPT shell artifacts still present: ${dptArtifacts.map { it.name }.joinToString(", ")}")
        }

        val dexEntries = entries.filter { it.isDex }
        val nativeEntries = entries.filter { it.isNativeLib }

        return ApkValidationResult(
            structureValid = errors.isEmpty() || errors.all { it.startsWith("DEX ") },
            manifestValid = hasManifest,
            dexValid = dexValid && hasManifest,
            entries = entries,
            dexEntries = dexEntries,
            nativeLibEntries = nativeEntries,
            errors = errors,
            warnings = warnings,
            totalSize = apkFile.length(),
        )
    }

    /**
     * Quick check: does the APK contain at least one valid DEX?
     */
    fun hasValidDex(apkFile: File): Boolean {
        return try {
            ZipFile(apkFile).use { zip ->
                val dexEntries = zip.entries().toList().filter {
                    it.name.matches(DEX_NAME)
                }
                dexEntries.any { entry ->
                    val bytes = zip.getInputStream(entry).use { it.readBytes() }
                    DexValidator.validate(bytes).isEmpty()
                }
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Get the list of DEX entry names in the APK.
     */
    fun listDexEntries(apkFile: File): List<String> {
        return try {
            ZipFile(apkFile).use { zip ->
                zip.entries().toList()
                    .filter { it.name.matches(DEX_NAME) }
                    .map { it.name }
                    .sorted()
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Get the list of native library entry names in the APK.
     */
    fun listNativeLibs(apkFile: File): List<String> {
        return try {
            ZipFile(apkFile).use { zip ->
                zip.entries().toList()
                    .filter { it.name.startsWith("lib/") && it.name.endsWith(".so") }
                    .map { it.name }
                    .sorted()
            }
        } catch (_: Exception) {
            emptyList()
        }
    }
}
