package com.dpt.unpack.privilege

/**
 * Shizuku provider for ADB/root-level access without full su.
 *
 * Shizuku provides a service that runs with ADB or root privileges.
 * Apps communicate with it via IPC (AIDL or Binder).
 *
 * This provider is designed to work with the Shizuku API:
 * 1. The Android app must initialize Shizuku and obtain a binder
 * 2. The binder is passed to this provider via [initialize]
 * 3. Once initialized, commands are executed via the Shizuku service
 *
 * If Shizuku is not running or the user hasn't granted permission,
 * [isAvailable] returns false and operations fail with structured errors.
 *
 * Reference: https://github.com/RikkaApps/Shizuku
 */
class ShizukuProvider : PrivilegeProvider {

    override val level: PrivilegeLevel = PrivilegeLevel.SHIZUKU
    override val displayName: String = "Shizuku (ADB)"

    private var binder: Any? = null
    private var initialized: Boolean = false

    /**
     * Initialize with a Shizuku binder obtained from the Android app.
     * Must be called before any operations.
     *
     * @param shizukuBinder the binder object from Shizuku API (typically IMiddlewareService)
     */
    fun initialize(shizukuBinder: Any?) {
        this.binder = shizukuBinder
        this.initialized = shizukuBinder != null
    }

    override fun isAvailable(): Boolean {
        if (!initialized) return false
        return try {
            val result = exec("id")
            result is PrivilegeResult.Success && result.output.contains("uid=")
        } catch (_: Exception) {
            false
        }
    }

    override fun exec(command: String, timeoutMs: Long): PrivilegeResult {
        if (!initialized) {
            return PrivilegeResult.Failure(
                PrivilegeError.Unavailable(
                    PrivilegeLevel.SHIZUKU,
                    PrivilegeLevel.NORMAL,
                    "Shizuku not initialized. Call initialize() with a valid binder."
                )
            )
        }
        return try {
            val b = binder ?: throw IllegalStateException("binder is null")
            val method = b.javaClass.getMethod(
                "newProcess",
                Array<String>::class.java,
                String::class.java,
                String::class.java
            )
            val process = method.invoke(b, arrayOf("sh", "-c", command), null, null)
            val inputStream = process.javaClass.getMethod("getInputStream").invoke(process) as java.io.InputStream
            val errorStream = process.javaClass.getMethod("getErrorStream").invoke(process) as java.io.InputStream
            val exitCode = process.javaClass.getMethod("waitFor").invoke(process) as Int
            val stdout = inputStream.bufferedReader().readText()
            val stderr = errorStream.bufferedReader().readText()
            if (exitCode == 0) {
                PrivilegeResult.Success(stdout.trim())
            } else {
                PrivilegeResult.Failure(
                    PrivilegeError.ExecutionFailed(command, exitCode, stderr.trim())
                )
            }
        } catch (e: Exception) {
            PrivilegeResult.Failure(
                PrivilegeError.ProviderError("Shizuku", e.message ?: "unknown error")
            )
        }
    }

    override fun installApk(apkPath: String): PrivilegeResult {
        return exec("pm install -r $apkPath")
    }

    override fun launchApp(packageName: String, activity: String?): PrivilegeResult {
        val target = if (activity != null) "$packageName/$activity" else packageName
        return exec("am start -n $target 2>/dev/null || monkey -p $packageName 1")
    }

    override fun pullFile(devicePath: String, localPath: String): PrivilegeResult {
        return exec("cat $devicePath")
    }

    override fun pushFile(localPath: String, devicePath: String): PrivilegeResult {
        return PrivilegeResult.Failure(
            PrivilegeError.NotSupported("pushFile via Shizuku", level)
        )
    }

    override fun readFile(devicePath: String): PrivilegeResult {
        return exec("cat $devicePath")
    }

    override fun listDir(devicePath: String): PrivilegeResult {
        return exec("ls -1 $devicePath")
    }

    override fun close() {
        binder = null
        initialized = false
    }
}
