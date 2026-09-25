package com.dpt.unpack.dynamic

import com.dpt.unpack.privilege.PrivilegeProvider
import java.io.File

/**
 * Manages the lifecycle of a target application on a device during analysis.
 *
 * Responsibilities:
 * - Install the APK to the device
 * - Launch the application
 * - Monitor whether the app is running
 * - Force-stop the app when analysis is complete
 * - Uninstall the app to clean up
 */
interface TargetApplicationManager {

    /**
     * Install an APK on the device.
     *
     * @param apkPath path to the APK file
     * @return success with install output, or failure with reason
     */
    fun install(apkPath: File): Result<String>

    /**
     * Launch the application.
     *
     * @param packageName the package to launch
     * @param activity optional explicit activity component
     * @return success with launch output, or failure with reason
     */
    fun launch(packageName: String, activity: String? = null): Result<String>

    /**
     * Check if the application is currently running.
     */
    fun isRunning(packageName: String): Boolean

    /**
     * Force-stop the application.
     */
    fun forceStop(packageName: String): Result<Unit>

    /**
     * Uninstall the application from the device.
     */
    fun uninstall(packageName: String): Result<Unit>

    /**
     * Capture a screenshot of the current device state (for documentation).
     *
     * @param destination where to save the screenshot
     * @return path to saved screenshot, or failure
     */
    fun screenshot(destination: File): Result<File> = Result.failure(
        UnsupportedOperationException("Screenshot not supported by this manager")
    )
}

/**
 * Default implementation using a [PrivilegeProvider] for device operations.
 */
class DefaultTargetApplicationManager(
    private val provider: PrivilegeProvider,
) : TargetApplicationManager {

    private val tag = "TargetApp"

    override fun install(apkPath: File): Result<String> {
        if (!apkPath.exists()) {
            return Result.failure(IllegalArgumentException("APK not found: ${apkPath.absolutePath}"))
        }
        return when (val result = provider.installApk(apkPath.absolutePath)) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> Result.success(result.output)
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> Result.failure(
                RuntimeException(result.error.humanReadable())
            )
        }
    }

    override fun launch(packageName: String, activity: String?): Result<String> {
        return when (val result = provider.launchApp(packageName, activity)) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> Result.success(result.output)
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> Result.failure(
                RuntimeException(result.error.humanReadable())
            )
        }
    }

    override fun isRunning(packageName: String): Boolean {
        return when (val result = provider.exec("pidof $packageName")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> result.output.isNotBlank()
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> false
        }
    }

    override fun forceStop(packageName: String): Result<Unit> {
        return when (val result = provider.exec("am force-stop $packageName")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> Result.success(Unit)
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> Result.failure(
                RuntimeException(result.error.humanReadable())
            )
        }
    }

    override fun uninstall(packageName: String): Result<Unit> {
        return when (val result = provider.exec("pm uninstall $packageName")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> Result.success(Unit)
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> Result.failure(
                RuntimeException(result.error.humanReadable())
            )
        }
    }

    override fun screenshot(destination: File): Result<File> {
        val devicePath = "/sdcard/dpt_screenshot.png"
        return when (provider.exec("screencap -p $devicePath")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> {
                when (val pull = provider.readFile(devicePath)) {
                    is com.dpt.unpack.privilege.PrivilegeResult.Success -> {
                        try {
                            destination.parentFile?.mkdirs()
                            destination.writeBytes(
                                java.util.Base64.getDecoder().decode(pull.output)
                            )
                            Result.success(destination)
                        } catch (e: Exception) {
                            provider.exec("rm $devicePath")
                            Result.failure(e)
                        }
                    }
                    is com.dpt.unpack.privilege.PrivilegeResult.Failure -> {
                        Result.failure(RuntimeException(pull.error.humanReadable()))
                    }
                }
            }
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> Result.failure(
                UnsupportedOperationException("Screenshot failed")
            )
        }
    }
}
