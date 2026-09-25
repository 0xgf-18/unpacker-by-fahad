package com.dpt.unpack.processing

import java.io.File

/**
 * Status of a processing operation.
 */
enum class ProcessingStatus {
    /** Artifact processed successfully. */
    SUCCESS,
    /** Partially processed; some issues occurred. */
    PARTIAL,
    /** Processing failed. */
    FAILED,
    /** Input artifact is invalid or unreadable. */
    INVALID_INPUT,
    /** A required dependency is missing. */
    MISSING_DEPENDENCY,
    /** Device testing is required but not available. */
    DEVICE_REQUIRED,
    /** Operation not supported for this artifact type. */
    UNSUPPORTED,
    /** Status could not be determined. */
    UNKNOWN,
}

/**
 * Source engine that produced an artifact.
 */
enum class ArtifactSource {
    STATIC_ENGINE,
    DYNAMIC_ENGINE,
    MANUAL,
    UNKNOWN,
}

/**
 * Type of artifact.
 */
enum class ArtifactType {
    DEX,
    NATIVE_LIB,
    RESOURCE,
    MANIFEST,
    CONFIG,
    UNKNOWN,
}

/**
 * A single artifact discovered during analysis.
 */
data class Artifact(
    val file: File,
    val type: ArtifactType,
    val source: ArtifactSource,
    val name: String = file.name,
    val size: Long = file.length(),
    val metadata: Map<String, String> = emptyMap(),
)

/**
 * Structured result of a processing operation.
 */
data class ProcessingResult(
    val inputArtifact: Artifact,
    val status: ProcessingStatus,
    val outputArtifact: Artifact? = null,
    val validationErrors: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val processingTimeMs: Long = 0,
    val engine: String = "",
    val details: Map<String, String> = emptyMap(),
) {
    val isSuccess: Boolean get() = status == ProcessingStatus.SUCCESS
    val isPartial: Boolean get() = status == ProcessingStatus.PARTIAL
    val isFailed: Boolean get() = status == ProcessingStatus.FAILED

    fun summary(): String {
        val base = "[${status.name}] ${inputArtifact.name} (${inputArtifact.type.name})"
        return when {
            validationErrors.isNotEmpty() -> "$base — ${validationErrors.size} validation error(s)"
            warnings.isNotEmpty() -> "$base — ${warnings.size} warning(s)"
            else -> base
        }
    }
}

/**
 * Aggregated result of processing multiple artifacts.
 */
data class BatchProcessingResult(
    val results: List<ProcessingResult>,
    val totalTimeMs: Long,
) {
    val totalArtifacts: Int get() = results.size
    val successCount: Int get() = results.count { it.status == ProcessingStatus.SUCCESS }
    val partialCount: Int get() = results.count { it.status == ProcessingStatus.PARTIAL }
    val failedCount: Int get() = results.count { it.status == ProcessingStatus.FAILED }

    val dexResults: List<ProcessingResult>
        get() = results.filter { it.inputArtifact.type == ArtifactType.DEX }

    val summary: String
        get() = "Processed $totalArtifacts artifact(s): $successCount success, $partialCount partial, $failedCount failed (${totalTimeMs}ms)"
}
