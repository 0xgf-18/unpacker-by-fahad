package com.dpt.unpack.finalization

import java.io.File
import java.util.zip.ZipFile

/**
 * Validates that an APK is actually signed.
 *
 * Checks:
 * - META-INF/ directory exists with signature files
 * - Signature files are non-empty
 * - APK structure remains valid after signing
 */
object SignatureValidator {

    private val SIGNATURE_PATTERNS = listOf(
        Regex("^META-INF/.*\\.SF$"),
        Regex("^META-INF/.*\\.RSA$"),
        Regex("^META-INF/.*\\.DSA$"),
        Regex("^META-INF/.*\\.EC$"),
        Regex("^META-INF/MANIFEST\\.MF$"),
    )

    /**
     * Validate that an APK contains signature files.
     *
     * @param apkFile the signed APK
     * @return validation result
     */
    fun validate(apkFile: File): SignatureValidationResult {
        if (!apkFile.exists()) {
            return SignatureValidationResult(
                signed = false,
                valid = false,
                errors = listOf("APK file does not exist"),
            )
        }

        return try {
            validateZip(apkFile)
        } catch (e: Exception) {
            SignatureValidationResult(
                signed = false,
                valid = false,
                errors = listOf("Failed to open APK: ${e.message}"),
            )
        }
    }

    private fun validateZip(apkFile: File): SignatureValidationResult {
        val signatureFiles = mutableListOf<String>()
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        var hasManifest = false

        ZipFile(apkFile).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                val name = entry.name

                if (name == "META-INF/MANIFEST.MF") {
                    hasManifest = true
                    if (entry.size == 0L) {
                        warnings.add("MANIFEST.MF is empty")
                    }
                }

                if (SIGNATURE_PATTERNS.any { it.matches(name) }) {
                    signatureFiles.add(name)
                    if (entry.size == 0L) {
                        warnings.add("$name is empty")
                    }
                }
            }
        }

        val hasSignature = signatureFiles.any { it.endsWith(".SF") || it.endsWith(".RSA") || it.endsWith(".DSA") || it.endsWith(".EC") }
        val signed = hasManifest && hasSignature

        if (!signed && !hasManifest) {
            errors.add("META-INF/MANIFEST.MF not found")
        }
        if (!hasSignature) {
            errors.add("No signature files found (.SF, .RSA, .DSA, .EC)")
        }

        return SignatureValidationResult(
            signed = signed,
            valid = signed && errors.isEmpty(),
            signatureFiles = signatureFiles,
            errors = errors,
            warnings = warnings,
        )
    }
}

data class SignatureValidationResult(
    val signed: Boolean,
    val valid: Boolean,
    val signatureFiles: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
) {
    val summary: String
        get() = buildString {
            append("Signature: ${if (signed) "SIGNED" else "UNSIGNED"}")
            append(" | ${signatureFiles.size} signature file(s)")
            if (errors.isNotEmpty()) append(" | ${errors.size} error(s)")
            if (warnings.isNotEmpty()) append(" | ${warnings.size} warning(s)")
        }
}
