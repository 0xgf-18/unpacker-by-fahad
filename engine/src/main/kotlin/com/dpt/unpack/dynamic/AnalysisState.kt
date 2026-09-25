package com.dpt.unpack.dynamic

/**
 * State machine for dynamic analysis jobs.
 *
 * Lifecycle:
 * IDLE → PREPARING → INSTALLING → LAUNCHING → MONITORING → COLLECTING → VALIDATING → COMPLETE
 *                                                            ↓
 *                                                         STOPPING
 *                                                            ↓
 *                                                        STOPPED
 *
 * Any state can transition to ERROR or CANCELLED.
 */
enum class AnalysisPhase {
    IDLE,
    PREPARING,
    INSTALLING,
    LAUNCHING,
    MONITORING,
    COLLECTING,
    VALIDATING,
    COMPLETE,
    STOPPING,
    STOPPED,
    ERROR,
    CANCELLED,
}

/**
 * Immutable snapshot of analysis job state.
 */
data class AnalysisState(
    val phase: AnalysisPhase = AnalysisPhase.IDLE,
    val message: String = "",
    val progress: Float = 0f,
    val error: AnalysisError? = null,
    val metadata: Map<String, String> = emptyMap(),
) {
    val isActive: Boolean
        get() = phase in setOf(
            AnalysisPhase.PREPARING,
            AnalysisPhase.INSTALLING,
            AnalysisPhase.LAUNCHING,
            AnalysisPhase.MONITORING,
            AnalysisPhase.COLLECTING,
            AnalysisPhase.VALIDATING,
        )

    val isTerminal: Boolean
        get() = phase in setOf(
            AnalysisPhase.COMPLETE,
            AnalysisPhase.STOPPED,
            AnalysisPhase.ERROR,
            AnalysisPhase.CANCELLED,
        )
}

/**
 * Structured errors for dynamic analysis.
 */
sealed class AnalysisError(override val message: String) : Exception(message) {
    data class InstallationFailed(val packageName: String, val reason: String) : AnalysisError("Installation failed for $packageName: $reason")
    data class LaunchFailed(val packageName: String, val reason: String) : AnalysisError("Launch failed for $packageName: $reason")
    data class MonitoringFailed(val reason: String) : AnalysisError("Monitoring failed: $reason")
    data class CollectionFailed(val reason: String) : AnalysisError("Collection failed: $reason")
    data class ValidationFailed(val reason: String) : AnalysisError("Validation failed: $reason")
    data class PrivilegeUnavailable(val reason: String) : AnalysisError("Required privileges unavailable: $reason")
    data class WorkspaceFailed(val reason: String) : AnalysisError("Workspace error: $reason")
    data class Timeout(val phase: AnalysisPhase, val timeoutMs: Long) : AnalysisError("Timeout during ${phase.name} after ${timeoutMs}ms")
    data class Internal(val msg: String, override val cause: Throwable? = null) : AnalysisError("Internal error: $msg")

    fun humanReadable(): String = when (this) {
        is InstallationFailed -> "Installation failed for $packageName: $reason"
        is LaunchFailed -> "Launch failed for $packageName: $reason"
        is MonitoringFailed -> "Monitoring failed: $reason"
        is CollectionFailed -> "Collection failed: $reason"
        is ValidationFailed -> "Validation failed: $reason"
        is PrivilegeUnavailable -> "Required privileges unavailable: $reason"
        is WorkspaceFailed -> "Workspace error: $reason"
        is Timeout -> "Timeout during ${phase.name} after ${timeoutMs}ms"
        is Internal -> "Internal error: $msg"
    }
}
