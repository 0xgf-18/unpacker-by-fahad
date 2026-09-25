package com.dpt.unpack.dynamic

import java.io.File
import java.util.zip.ZipFile

/**
 * Validates collected runtime payloads to determine whether they are
 * genuine, usable artifacts.
 *
 * Never reports a payload as recovered unless it passes validation.
 */
interface PayloadValidator {

    /**
     * Validate a single collected payload.
     *
     * @param payload the collected payload to validate
     * @return validation result with details
     */
    fun validate(payload: CollectedPayload): ValidationResult

    /**
     * Validate all payloads in a workspace and produce a summary report.
     *
     * @param payloads all collected payloads
     * @param workspace the workspace containing the artifacts
     * @return validation report
     */
    fun validateAll(payloads: List<CollectedPayload>, workspace: AnalysisWorkspace): ValidationReport
}

data class ValidationResult(
    val valid: Boolean,
    val confidence: Double,
    val details: String,
    val issues: List<String> = emptyList(),
)

data class ValidationReport(
    val totalPayloads: Int,
    val validPayloads: Int,
    val dexArtifacts: Int,
    val nativeArtifacts: Int,
    val overallConfidence: Double,
    val details: List<PayloadDetail>,
    val summary: String,
)

data class PayloadDetail(
    val payload: CollectedPayload,
    val result: ValidationResult,
)

/**
 * Default payload validator. Checks DEX structural validity and native ELF headers.
 */
class DefaultPayloadValidator : PayloadValidator {

    override fun validate(payload: CollectedPayload): ValidationResult {
        return when (payload.type) {
            PayloadType.DEX -> validateDex(payload)
            PayloadType.NATIVE_LIB -> validateElf(payload)
            PayloadType.MEMORY_DUMP -> validateMemoryDump(payload)
            PayloadType.CONFIG -> ValidationResult(true, 0.5, "Config file — cannot validate structure")
            PayloadType.OTHER -> ValidationResult(false, 0.0, "Unknown payload type")
        }
    }

    override fun validateAll(
        payloads: List<CollectedPayload>,
        workspace: AnalysisWorkspace,
    ): ValidationReport {
        val details = payloads.map { PayloadDetail(it, validate(it)) }
        val valid = details.filter { it.result.valid }
        val dexCount = valid.count { it.payload.type == PayloadType.DEX }
        val nativeCount = valid.count { it.payload.type == PayloadType.NATIVE_LIB }
        val avgConfidence = if (details.isNotEmpty()) {
            details.map { it.result.confidence }.average()
        } else 0.0

        val summary = when {
            payloads.isEmpty() -> "No payloads collected"
            valid.isEmpty() -> "Collected ${payloads.size} payloads but none passed validation"
            dexCount > 0 -> "Recovered $dexCount valid DEX artifact(s), $nativeCount native lib(s)"
            else -> "Recovered $nativeCount native artifact(s)"
        }

        return ValidationReport(
            totalPayloads = payloads.size,
            validPayloads = valid.size,
            dexArtifacts = dexCount,
            nativeArtifacts = nativeCount,
            overallConfidence = avgConfidence,
            details = details,
            summary = summary,
        )
    }

    private fun validateDex(payload: CollectedPayload): ValidationResult {
        val file = payload.file
        if (!file.exists()) {
            return ValidationResult(false, 0.0, "File does not exist", listOf("Missing file"))
        }
        if (file.length() < 112) {
            return ValidationResult(false, 0.0, "File too small for DEX (${file.length()} bytes)", listOf("Below minimum DEX size"))
        }

        val issues = mutableListOf<String>()
        try {
            val bytes = file.readBytes()
            val magic = String(bytes, 0, 8)
            if (!magic.startsWith("dex\n")) {
                issues.add("Invalid DEX magic: ${magic.trim()}")
            }

            // Check file size vs header-reported size
            val fileSize = bytes.size.toLong()
            val headerSize = ((bytes[36].toInt() and 0xFF) shl 24) or
                    ((bytes[37].toInt() and 0xFF) shl 16) or
                    ((bytes[38].toInt() and 0xFF) shl 8) or
                    (bytes[39].toInt() and 0xFF)

            // Validate that the file isn't truncated
            if (fileSize < headerSize) {
                issues.add("File truncated: ${fileSize} bytes < header size $headerSize")
            }

            // Validate section count is reasonable
            val sectionCount = ((bytes[32].toInt() and 0xFF) shl 24) or
                    ((bytes[33].toInt() and 0xFF) shl 16) or
                    ((bytes[34].toInt() and 0xFF) shl 8) or
                    (bytes[35].toInt() and 0xFF)
            if (sectionCount == 0 || sectionCount > 100) {
                issues.add("Unreasonable section count: $sectionCount")
            }

            val confidence = when {
                issues.isEmpty() && payload.confidence > 0.8 -> payload.confidence
                issues.isEmpty() -> 0.85
                else -> (payload.confidence * 0.5).coerceIn(0.0, 1.0)
            }

            return ValidationResult(
                valid = issues.isEmpty(),
                confidence = confidence,
                details = "DEX ${magic.trim()} — ${file.length()} bytes, $sectionCount sections",
                issues = issues,
            )
        } catch (e: Exception) {
            return ValidationResult(false, 0.0, "Failed to read DEX: ${e.message}", listOf(e.message ?: "read error"))
        }
    }

    private fun validateElf(payload: CollectedPayload): ValidationResult {
        val file = payload.file
        if (!file.exists()) {
            return ValidationResult(false, 0.0, "File does not exist", listOf("Missing file"))
        }
        if (file.length() < 16) {
            return ValidationResult(false, 0.0, "File too small for ELF (${file.length()} bytes)", listOf("Below minimum ELF size"))
        }

        try {
            val bytes = file.readBytes()
            if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
                bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()) {
                return ValidationResult(false, 0.0, "Invalid ELF magic", listOf("Not an ELF file"))
            }
            val is64bit = bytes[4] == 2.toByte()
            val arch = if (is64bit) "64-bit" else "32-bit"
            return ValidationResult(true, 0.8, "ELF $arch native library — ${file.length()} bytes")
        } catch (e: Exception) {
            return ValidationResult(false, 0.0, "Failed to read ELF: ${e.message}", listOf(e.message ?: "read error"))
        }
    }

    private fun validateMemoryDump(payload: CollectedPayload): ValidationResult {
        val file = payload.file
        if (!file.exists() || file.length() == 0L) {
            return ValidationResult(false, 0.0, "Empty memory dump", listOf("No data"))
        }
        // Memory dumps are inherently unvalidated — we just check if they exist and have data
        return ValidationResult(
            valid = file.length() > 1024,
            confidence = 0.3,
            details = "Memory dump — ${file.length()} bytes (unvalidated content)",
        )
    }
}
