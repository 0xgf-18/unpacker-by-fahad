package com.dpt.unpack.privilege

/**
 * Abstraction for privileged operations on Android devices.
 *
 * Implementations:
 * - [RootProvider]: full root shell access via su
 * - [ShizukuProvider]: ADB/root Shizuku IPC access
 * - [NormalProvider]: non-privileged fallback (limited capabilities)
 *
 * All implementations must be safe to call from any thread.
 * Unpack engines should depend on this interface, never on concrete providers.
 */
interface PrivilegeProvider {

    /** The privilege level this provider offers. */
    val level: PrivilegeLevel

    /** Human-readable name for logging (e.g. "Root (su)", "Shizuku", "Normal"). */
    val displayName: String

    /**
     * Check whether this provider is currently available and operational.
     * Must not perform any privileged operations itself.
     */
    fun isAvailable(): Boolean

    /**
     * Execute a shell command with the provider's privilege level.
     *
     * @param command the shell command to execute
     * @param timeoutMs maximum time to wait (0 = no timeout)
     * @return [PrivilegeResult.Success] with stdout, or [PrivilegeResult.Failure]
     */
    fun exec(command: String, timeoutMs: Long = 10_000): PrivilegeResult

    /**
     * Install an APK on the device.
     *
     * @param apkPath absolute path to the APK file on the device filesystem
     * @return [PrivilegeResult.Success] or [PrivilegeResult.Failure]
     */
    fun installApk(apkPath: String): PrivilegeResult

    /**
     * Launch an application by package name.
     *
     * @param packageName the package to launch
     * @param activity explicit activity component (null = default launcher)
     * @return [PrivilegeResult.Success] or [PrivilegeResult.Failure]
     */
    fun launchApp(packageName: String, activity: String? = null): PrivilegeResult

    /**
     * Pull a file from the device to a local path.
     * Only meaningful for providers with filesystem access (Root, Shizuku).
     *
     * @param devicePath path on the device
     * @param localPath destination path on the host
     * @return [PrivilegeResult.Success] or [PrivilegeResult.Failure]
     */
    fun pullFile(devicePath: String, localPath: String): PrivilegeResult

    /**
     * Push a local file to the device.
     *
     * @param localPath source path on the host
     * @param devicePath destination path on the device
     * @return [PrivilegeResult.Success] or [PrivilegeResult.Failure]
     */
    fun pushFile(localPath: String, devicePath: String): PrivilegeResult

    /**
     * Read a file from the device filesystem.
     *
     * @param devicePath path on the device
     * @return [PrivilegeResult.Success] with file contents, or [PrivilegeResult.Failure]
     */
    fun readFile(devicePath: String): PrivilegeResult

    /**
     * List files in a device directory.
     *
     * @param devicePath directory path on the device
     * @return [PrivilegeResult.Success] with newline-separated file list, or [PrivilegeResult.Failure]
     */
    fun listDir(devicePath: String): PrivilegeResult

    /**
     * Stop/clean up any resources held by this provider.
     * Called when the provider is no longer needed.
     */
    fun close() {}
}
