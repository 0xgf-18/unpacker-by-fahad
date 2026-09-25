package com.dpt.unpack.finalization

import com.dpt.unpack.rebuild.RebuildResult
import com.dpt.unpack.rebuild.RebuildStatus
import java.io.File

/**
 * Aggregated result of the entire finalization pipeline:
 * REBUILD → SIGN → VERIFY → INSTALL → LAUNCH
 */
data class FinalizationResult(
    val rebuildResult: RebuildResult? = null,
    val signingResult: SigningResult? = null,
    val signatureValidation: SignatureValidationResult? = null,
    val installationResult: InstallationResult? = null,
    val launchResult: LaunchResult? = null,
    val totalTimeMs: Long = 0,
) {
    val rebuildStatus: RebuildStatus
        get() = rebuildResult?.status ?: RebuildStatus.UNKNOWN

    val signingStatus: SigningStatus
        get() = signingResult?.status ?: SigningStatus.UNKNOWN

    val installStatus: InstallStatus
        get() = installationResult?.status ?: InstallStatus.UNKNOWN

    val launchStatus: LaunchStatus
        get() = launchResult?.status ?: LaunchStatus.UNKNOWN

    val isFullySuccessful: Boolean
        get() = rebuildStatus == RebuildStatus.SUCCESS &&
            signingStatus == SigningStatus.SUCCESS &&
            installStatus == InstallStatus.SUCCESS &&
            launchStatus == LaunchStatus.SUCCESS

    val signedApk: File?
        get() = signingResult?.outputApk

    val summary: String
        get() = buildString {
            append("Rebuild: ${rebuildStatus.name}")
            append(" | Sign: ${signingStatus.name}")
            append(" | Install: ${installStatus.name}")
            append(" | Launch: ${launchStatus.name}")
            if (!isFullySuccessful) {
                val issues = mutableListOf<String>()
                if (rebuildStatus != RebuildStatus.SUCCESS) issues.add("rebuild")
                if (signingStatus != SigningStatus.SUCCESS) issues.add("signing")
                if (installStatus != InstallStatus.SUCCESS) issues.add("install")
                if (launchStatus != LaunchStatus.SUCCESS) issues.add("launch")
                append(" | Issues: ${issues.joinToString(", ")}")
            }
        }

    val detailedReport: String
        get() = buildString {
            appendLine("=== FINALIZATION REPORT ===")
            appendLine()

            rebuildResult?.let {
                appendLine("REBUILD: ${it.status.name}")
                it.outputApk?.let { apk -> appendLine("  Output: ${apk.absolutePath} (${it.outputSize} bytes)") }
                appendLine("  DEX: ${it.dexCount} | Native: ${it.nativeLibCount}")
                if (it.validationErrors.isNotEmpty()) {
                    appendLine("  Errors: ${it.validationErrors.joinToString("; ")}")
                }
                appendLine()
            }

            signingResult?.let {
                appendLine("SIGNING: ${it.status.name}")
                it.outputApk?.let { apk -> appendLine("  Output: ${apk.absolutePath}") }
                if (it.warnings.isNotEmpty()) {
                    appendLine("  Warnings: ${it.warnings.joinToString("; ")}")
                }
                if (it.errors.isNotEmpty()) {
                    appendLine("  Errors: ${it.errors.joinToString("; ")}")
                }
                appendLine()
            }

            signatureValidation?.let {
                appendLine("SIGNATURE: ${if (it.signed) "VALID" else "INVALID"}")
                appendLine("  Files: ${it.signatureFiles.joinToString(", ")}")
                appendLine()
            }

            installationResult?.let {
                appendLine("INSTALL: ${it.status.name}")
                appendLine("  Package: ${it.packageName ?: "unknown"}")
                it.installedVersion?.let { v -> appendLine("  Version: $v") }
                appendLine("  Verified: ${it.verified}")
                if (it.errors.isNotEmpty()) {
                    appendLine("  Errors: ${it.errors.joinToString("; ")}")
                }
                appendLine()
            }

            launchResult?.let {
                appendLine("LAUNCH: ${it.status.name}")
                appendLine("  Package: ${it.packageName}")
                appendLine("  Process running: ${it.processRunning}")
                if (it.errors.isNotEmpty()) {
                    appendLine("  Errors: ${it.errors.joinToString("; ")}")
                }
                appendLine()
            }

            appendLine("TOTAL TIME: ${totalTimeMs}ms")
        }
}
