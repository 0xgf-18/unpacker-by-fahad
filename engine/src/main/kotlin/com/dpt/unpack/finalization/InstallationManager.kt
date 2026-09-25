package com.dpt.unpack.finalization

import com.dpt.unpack.privilege.PrivilegeManager
import com.dpt.unpack.privilege.PrivilegeProvider
import java.io.File

/**
 * Manages APK installation on a target device.
 *
 * Uses the privilege abstraction from Phase 4 for device operations.
 * Distinguishes between "command accepted" and "actually installed".
 */
class InstallationManager(private val privilegeManager: PrivilegeManager) {

    private var activeProvider: PrivilegeProvider? = null

    /**
     * Install an APK on the connected device.
     *
     * Before installation:
     * - verify APK exists
     * - verify APK is structurally valid
     * - verify it is signed
     * - verify privilege provider is available
     *
     * @param apkFile the signed APK to install
     * @param packageName expected package name for post-install verification
     * @return installation result
     */
    fun install(apkFile: File, packageName: String? = null): InstallationResult {
        val startTime = System.currentTimeMillis()

        // Pre-installation checks
        if (!apkFile.exists()) {
            return InstallationResult(
                status = InstallStatus.FAILED,
                packageName = packageName,
                errors = listOf("APK file does not exist: ${apkFile.absolutePath}"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        if (apkFile.length() == 0L) {
            return InstallationResult(
                status = InstallStatus.FAILED,
                packageName = packageName,
                errors = listOf("APK file is empty"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        // Validate APK is signed
        val sigResult = SignatureValidator.validate(apkFile)
        if (!sigResult.signed) {
            return InstallationResult(
                status = InstallStatus.FAILED,
                packageName = packageName,
                errors = listOf("APK is not signed: ${sigResult.summary}"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        // Select privilege provider
        val provider = selectProvider()
        if (provider == null) {
            return InstallationResult(
                status = InstallStatus.BLOCKED,
                packageName = packageName,
                errors = listOf("No privilege provider available (root/Shizuku/normal)"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }
        activeProvider = provider

        // Execute installation
        val installResult = provider.installApk(apkFile.absolutePath)
        return when (installResult) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> {
                // Verify installation
                val verified = if (packageName != null) {
                    verifyPackage(provider, packageName)
                } else {
                    PackageVerification(verified = false, reason = "No package name provided for verification")
                }

                InstallationResult(
                    status = if (verified.verified) InstallStatus.SUCCESS else InstallStatus.PARTIAL,
                    packageName = packageName,
                    installedPackageName = verified.installedName,
                    installedVersion = verified.installedVersion,
                    verified = verified.verified,
                    warnings = if (!verified.verified) listOf("Install command succeeded but verification failed: ${verified.reason}") else emptyList(),
                    timeMs = System.currentTimeMillis() - startTime,
                    details = mapOf(
                        "provider" to provider.displayName,
                        "output" to installResult.output,
                    ),
                )
            }
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> {
                InstallationResult(
                    status = InstallStatus.FAILED,
                    packageName = packageName,
                    errors = listOf("Installation failed: ${installResult.error.humanReadable()}"),
                    timeMs = System.currentTimeMillis() - startTime,
                )
            }
        }
    }

    /**
     * Uninstall a package from the device.
     */
    fun uninstall(packageName: String): UninstallResult {
        val provider = activeProvider ?: selectProvider()
            ?: return UninstallResult(
                success = false,
                errors = listOf("No privilege provider available"),
            )

        return when (val result = provider.exec("pm uninstall $packageName")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> {
                UninstallResult(success = true, output = result.output)
            }
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> {
                UninstallResult(
                    success = false,
                    errors = listOf(result.error.humanReadable()),
                )
            }
        }
    }

    /**
     * Check if a package is installed on the device.
     */
    fun isInstalled(packageName: String): Boolean {
        val provider = activeProvider ?: return false
        return when (val result = provider.exec("pm path $packageName")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> result.output.isNotBlank()
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> false
        }
    }

    private fun verifyPackage(provider: PrivilegeProvider, packageName: String): PackageVerification {
        // Check if package exists
        val pathResult = provider.exec("pm path $packageName")
        if (pathResult is com.dpt.unpack.privilege.PrivilegeResult.Failure ||
            (pathResult is com.dpt.unpack.privilege.PrivilegeResult.Success && pathResult.output.isBlank())) {
            return PackageVerification(verified = false, reason = "Package not found on device")
        }

        // Get version info
        val versionResult = provider.exec("dumpsys package $packageName | grep versionName")
        val version = if (versionResult is com.dpt.unpack.privilege.PrivilegeResult.Success) {
            versionResult.output.lines()
                .firstOrNull { it.contains("versionName") }
                ?.substringAfter("=")
                ?.trim()
        } else null

        return PackageVerification(
            verified = true,
            installedName = packageName,
            installedVersion = version,
        )
    }

    private fun selectProvider(): PrivilegeProvider? {
        val levels = listOf(
            com.dpt.unpack.privilege.PrivilegeLevel.ROOT,
            com.dpt.unpack.privilege.PrivilegeLevel.SHIZUKU,
            com.dpt.unpack.privilege.PrivilegeLevel.NORMAL,
        )
        for (level in levels) {
            val p = privilegeManager.select(level)
            if (p != null && p.isAvailable()) return p
        }
        return null
    }
}

enum class InstallStatus {
    SUCCESS,
    PARTIAL,
    FAILED,
    BLOCKED,
    UNKNOWN,
}

data class InstallationResult(
    val status: InstallStatus,
    val packageName: String?,
    val installedPackageName: String? = null,
    val installedVersion: String? = null,
    val verified: Boolean = false,
    val warnings: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
    val timeMs: Long = 0,
    val details: Map<String, String> = emptyMap(),
) {
    val summary: String
        get() = buildString {
            append("[${status.name}] $packageName")
            installedVersion?.let { append(" v$it") }
            if (!verified) append(" (unverified)")
            if (errors.isNotEmpty()) append(" — ${errors.size} error(s)")
        }
}

data class PackageVerification(
    val verified: Boolean,
    val installedName: String? = null,
    val installedVersion: String? = null,
    val reason: String = "",
)

data class UninstallResult(
    val success: Boolean,
    val output: String = "",
    val errors: List<String> = emptyList(),
)
