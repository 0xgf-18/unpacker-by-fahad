package com.dpt.unpack.rebuild

import java.io.File

/**
 * Status of a rebuild operation.
 */
enum class RebuildStatus {
    SUCCESS,
    PARTIAL,
    FAILED,
    INVALID_INPUT,
    MISSING_DEPENDENCY,
    UNSUPPORTED,
    UNKNOWN,
}

/**
 * Status of a validation check.
 */
enum class ValidationStatus {
    PASS,
    FAIL,
    BLOCKED,
    UNKNOWN,
}

/**
 * Structured result of an APK rebuild operation.
 */
data class RebuildResult(
    val status: RebuildStatus,
    val inputApk: File?,
    val outputApk: File?,
    val outputSize: Long = 0,
    val dexCount: Int = 0,
    val nativeLibCount: Int = 0,
    val manifestStatus: ValidationStatus = ValidationStatus.UNKNOWN,
    val apkStructureStatus: ValidationStatus = ValidationStatus.UNKNOWN,
    val dexValidationStatus: ValidationStatus = ValidationStatus.UNKNOWN,
    val validationErrors: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val processingTimeMs: Long = 0,
    val details: Map<String, String> = emptyMap(),
) {
    val summary: String
        get() = buildString {
            append("[${status.name}] ")
            outputApk?.let { append(it.name) }
            append(" (${outputSize} bytes, $dexCount DEX)")
            if (validationErrors.isNotEmpty()) {
                append(" — ${validationErrors.size} error(s)")
            }
            if (warnings.isNotEmpty()) {
                append(" — ${warnings.size} warning(s)")
            }
        }

    val isSuccess: Boolean get() = status == RebuildStatus.SUCCESS
    val isPartial: Boolean get() = status == RebuildStatus.PARTIAL
    val isFailed: Boolean get() = status == RebuildStatus.FAILED
}

/**
 * Result of validating a rebuilt APK.
 */
data class ApkValidationResult(
    val structureValid: Boolean,
    val manifestValid: Boolean,
    val dexValid: Boolean,
    val entries: List<ApkEntry> = emptyList(),
    val dexEntries: List<ApkEntry> = emptyList(),
    val nativeLibEntries: List<ApkEntry> = emptyList(),
    val errors: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val totalSize: Long = 0,
) {
    val isValid: Boolean get() = structureValid && manifestValid && dexValid && errors.isEmpty()

    val summary: String
        get() = buildString {
            append("APK: ${if (structureValid) "VALID" else "INVALID"}")
            append(" | Manifest: ${if (manifestValid) "VALID" else "INVALID"}")
            append(" | DEX: ${if (dexValid) "VALID" else "INVALID"}")
            append(" | Entries: ${entries.size} (${dexEntries.size} DEX, ${nativeLibEntries.size} native)")
        }
}

/**
 * Information about a single entry in an APK.
 */
data class ApkEntry(
    val name: String,
    val size: Long,
    val compressedSize: Long,
    val method: Int,
    val crc: Long,
) {
    val isDex: Boolean get() = name.endsWith(".dex") && name.startsWith("classes")
    val isNativeLib: Boolean get() = name.startsWith("lib/") && name.endsWith(".so")
    val isStored: Boolean get() = method == 0
    val isDeflated: Boolean get() = method == 8
}
