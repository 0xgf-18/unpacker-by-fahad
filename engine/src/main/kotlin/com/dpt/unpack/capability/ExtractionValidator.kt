package com.dpt.unpack.capability

import com.dpt.unpack.axml.AxmlManifest
import com.dpt.unpack.validate.DexValidator
import java.io.File
import java.util.zip.ZipFile

/**
 * Validates extraction/unpacking outputs to ensure structural integrity.
 */
object ExtractionValidator {

    data class ValidationResult(
        val valid: Boolean,
        val issues: List<String>,
        val dexCount: Int = 0,
        val hasManifest: Boolean = false,
        val packageName: String? = null,
        val entryCount: Int = 0,
        val fileSize: Long = 0,
    )

    fun validateApk(apk: File): ValidationResult {
        val issues = mutableListOf<String>()

        if (!apk.exists()) {
            return ValidationResult(false, listOf("Output file does not exist"))
        }
        if (apk.length() == 0L) {
            return ValidationResult(false, listOf("Output file is empty"))
        }

        var dexCount = 0
        var hasManifest = false
        var packageName: String? = null
        var entryCount = 0

        try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries().asSequence().map { it.name }.toList()
                entryCount = entries.size

                for (entry in entries) {
                    if (entry.startsWith("classes") && entry.endsWith(".dex")) {
                        dexCount++
                        val bytes = zip.getInputStream(zip.getEntry(entry)).use { it.readBytes() }
                        val problems = DexValidator.validate(bytes)
                        if (problems.isNotEmpty()) {
                            issues.add("$entry: ${problems.joinToString()}")
                        }
                    }
                    if (entry == "AndroidManifest.xml") {
                        hasManifest = true
                        val bytes = zip.getInputStream(zip.getEntry(entry)).use { it.readBytes() }
                        try {
                            val parsed = AxmlManifest.parse(bytes)
                            packageName = parsed.startTags.firstOrNull {
                                val name = parsed.strings.getOrElse(it.nameId) { "" }
                                name == "manifest"
                            }?.let { t ->
                                t.attrs.firstOrNull {
                                    val attrName = parsed.strings.getOrElse(it.nameField.toInt()) { "" }
                                    attrName == "package"
                                }?.valueText
                            }
                        } catch (e: Exception) {
                            issues.add("AndroidManifest.xml: parse error: ${e.message}")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            issues.add("ZIP structure error: ${e.message}")
        }

        if (dexCount == 0) {
            issues.add("No DEX files found in output")
        }
        if (!hasManifest) {
            issues.add("No AndroidManifest.xml found in output")
        }

        val valid = issues.isEmpty() && dexCount > 0 && hasManifest
        return ValidationResult(valid, issues, dexCount, hasManifest, packageName, entryCount, apk.length())
    }

    fun validateExtractedDex(dexFile: File): ValidationResult {
        val issues = mutableListOf<String>()
        if (!dexFile.exists()) {
            return ValidationResult(false, listOf("DEX file does not exist"))
        }
        if (dexFile.length() == 0L) {
            return ValidationResult(false, listOf("DEX file is empty"))
        }
        val bytes = dexFile.readBytes()
        val problems = DexValidator.validate(bytes)
        issues.addAll(problems)

        val magic = bytes.copyOfRange(0, 4)
        val isDex = magic[0] == 0x64.toByte() && magic[1] == 0x65.toByte() &&
            magic[2] == 0x78.toByte() && magic[3] == 0x0a.toByte()
        if (!isDex) {
            issues.add("File does not have DEX magic bytes")
        }

        return ValidationResult(issues.isEmpty(), issues, fileSize = dexFile.length())
    }
}
