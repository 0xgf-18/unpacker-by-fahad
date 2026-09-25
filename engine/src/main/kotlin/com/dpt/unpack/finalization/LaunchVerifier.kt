package com.dpt.unpack.finalization

import com.dpt.unpack.privilege.PrivilegeManager
import com.dpt.unpack.privilege.PrivilegeProvider

/**
 * Verifies that an application can be launched on the device.
 *
 * After requesting launch:
 * - verify the application process/activity actually starts
 * - capture launch errors
 * - distinguish "launch command accepted" from "application successfully launched"
 */
class LaunchVerifier(private val privilegeManager: PrivilegeManager) {

    private var activeProvider: PrivilegeProvider? = null

    /**
     * Launch an application and verify it started.
     *
     * @param packageName the package to launch
     * @param activity optional explicit activity component
     * @param waitMs time to wait after launch before checking (default 3000ms)
     * @return launch result
     */
    fun launch(packageName: String, activity: String? = null, waitMs: Long = 3000): LaunchResult {
        val startTime = System.currentTimeMillis()

        val provider = selectProvider()
        if (provider == null) {
            return LaunchResult(
                status = LaunchStatus.BLOCKED,
                packageName = packageName,
                errors = listOf("No privilege provider available"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }
        activeProvider = provider

        // Launch the application
        val target = if (activity != null) "$packageName/$activity" else packageName
        val launchResult = provider.exec("am start -n $target 2>&1 || monkey -p $packageName 1 2>&1")

        return when (launchResult) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> {
                val output = launchResult.output

                // Check if launch command was rejected
                if (output.contains("Error") || output.contains("does not exist") || output.contains("not found")) {
                    return LaunchResult(
                        status = LaunchStatus.FAILED,
                        packageName = packageName,
                        errors = listOf("Launch rejected: $output"),
                        timeMs = System.currentTimeMillis() - startTime,
                    )
                }

                // Wait for app to start
                Thread.sleep(waitMs)

                // Verify process is running
                val isRunning = checkProcessRunning(provider, packageName)

                LaunchResult(
                    status = if (isRunning) LaunchStatus.SUCCESS else LaunchStatus.FAILED,
                    packageName = packageName,
                    processRunning = isRunning,
                    launchOutput = output,
                    errors = if (!isRunning) listOf("Launch command accepted but process not found after ${waitMs}ms") else emptyList(),
                    timeMs = System.currentTimeMillis() - startTime,
                    details = mapOf(
                        "provider" to provider.displayName,
                        "target" to target,
                    ),
                )
            }
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> {
                LaunchResult(
                    status = LaunchStatus.FAILED,
                    packageName = packageName,
                    errors = listOf("Launch command failed: ${launchResult.error.humanReadable()}"),
                    timeMs = System.currentTimeMillis() - startTime,
                )
            }
        }
    }

    /**
     * Force-stop an application.
     */
    fun forceStop(packageName: String): Boolean {
        val provider = activeProvider ?: return false
        return when (provider.exec("am force-stop $packageName")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> true
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> false
        }
    }

    /**
     * Get the PID of a running package.
     */
    fun getPid(packageName: String): Int? {
        val provider = activeProvider ?: return null
        return when (val result = provider.exec("pidof $packageName")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> {
                result.output.trim().split("\\s+".toRegex()).firstOrNull()?.toIntOrNull()
            }
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> null
        }
    }

    private fun checkProcessRunning(provider: PrivilegeProvider, packageName: String): Boolean {
        return when (val result = provider.exec("pidof $packageName")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> result.output.isNotBlank()
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> false
        }
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

enum class LaunchStatus {
    SUCCESS,
    FAILED,
    BLOCKED,
    UNKNOWN,
}

data class LaunchResult(
    val status: LaunchStatus,
    val packageName: String,
    val processRunning: Boolean = false,
    val launchOutput: String = "",
    val warnings: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
    val timeMs: Long = 0,
    val details: Map<String, String> = emptyMap(),
) {
    val summary: String
        get() = buildString {
            append("[${status.name}] $packageName")
            if (processRunning) append(" (running)")
            if (errors.isNotEmpty()) append(" — ${errors.size} error(s)")
        }
}
