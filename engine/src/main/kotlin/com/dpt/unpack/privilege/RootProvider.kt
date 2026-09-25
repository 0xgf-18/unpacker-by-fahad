package com.dpt.unpack.privilege

import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Root provider using the `su` binary.
 *
 * Discovery order:
 * 1. $DPT_SU_PATH (explicit path to su)
 * 2. Common paths: /system/bin/su, /system/xbin/su, /sbin/su
 * 3. `su` on PATH
 *
 * Does not hard-code any specific root manager (Magisk, KernelSU, APatch, etc.).
 * Any working `su` binary is accepted.
 *
 * Also detects KernelSU/Magisk and reports authorization status.
 */
class RootProvider : PrivilegeProvider {

    override val level: PrivilegeLevel = PrivilegeLevel.ROOT
    override val displayName: String = "Root (su)"

    private var cachedSuPath: String? = null
    private var cachedAvailable: Boolean? = null
    private var cachedRootError: String? = null

    /** Path to the su binary that was found, or null. */
    val suPath: String? get() = cachedSuPath ?: findSu()

    /** Human-readable diagnostic for root status. */
    val rootDiagnostic: String get() {
        val path = cachedSuPath ?: findSu()
        if (path == null) return "su binary not found"
        val err = cachedRootError
        return if (err != null) "su@ $path: $err" else "su@ $path: OK"
    }

    override fun isAvailable(): Boolean {
        cachedAvailable?.let { return it }
        val path = findSu()
        cachedSuPath = path
        val result = path?.let { testRoot(it) }
        val available = result?.first ?: false
        cachedAvailable = available
        cachedRootError = result?.second
        return available
    }

    private fun findSu(): String? {
        System.getenv("DPT_SU_PATH")?.takeIf { it.isNotBlank() }?.let { p ->
            if (File(p).canExecute()) return p
        }
        for (candidate in SU_CANDIDATES) {
            val f = File(candidate)
            if (f.canExecute()) return candidate
        }
        val path = System.getenv("PATH") ?: return null
        for (dir in path.split(File.pathSeparator)) {
            val f = File(dir, "su")
            if (f.isFile) return f.absolutePath
        }
        return null
    }

    /**
     * Tests su authorization. Returns (authorized, errorMessage).
     *
     * Error diagnosis:
     * - "Permission denied": KernelSU/Magisk not authorized for this app
     * - "timed out": su prompt may be waiting for user grant
     * - "not found": su binary missing
     */
    private fun testRoot(suPath: String): Pair<Boolean, String?> {
        return try {
            val pb = ProcessBuilder(suPath, "-c", "id")
            pb.redirectErrorStream(true)
            val proc = pb.start()
            proc.outputStream.close()
            val out = proc.inputStream.bufferedReader().readText()
            val exited = proc.waitFor(10, TimeUnit.SECONDS)
            if (!exited) {
                proc.destroyForcibly()
                return Pair(false, "su timed out (waiting for user authorization?)")
            }
            if (proc.exitValue() == 0 && out.contains("uid=0")) {
                Pair(true, null)
            } else {
                val diag = when {
                    out.contains("Permission denied") || out.contains("not allowed") ->
                        "su denied (grant root in KernelSU/Magisk manager)"
                    out.contains("not found") || out.contains("inaccessible") ->
                        "su binary exists but cannot be executed from app sandbox"
                    else -> "su exit=${proc.exitValue()}: ${out.trim().take(200)}"
                }
                Pair(false, diag)
            }
        } catch (e: java.io.IOException) {
            val msg = when {
                e.message?.contains("Permission denied") == true ->
                    "Permission denied: grant root to this app in KernelSU/Magisk"
                e.message?.contains("No such file") == true ->
                    "su binary not found at $suPath"
                else -> "Cannot execute su: ${e.message}"
            }
            Pair(false, msg)
        } catch (e: Exception) {
            Pair(false, "Root test failed: ${e.message}")
        }
    }

    override fun exec(command: String, timeoutMs: Long): PrivilegeResult {
        val su = cachedSuPath ?: findSu()
            ?: return PrivilegeResult.Failure(
                PrivilegeError.Unavailable(PrivilegeLevel.ROOT, PrivilegeLevel.NORMAL, "su binary not found")
            )
        return try {
            val p = Runtime.getRuntime().exec(arrayOf(su, "-c", command))
            val stdout = p.inputStream.bufferedReader().readText()
            val stderr = p.errorStream.bufferedReader().readText()
            val exited = p.waitFor()
            if (exited == 0) {
                PrivilegeResult.Success(stdout.trim())
            } else {
                PrivilegeResult.Failure(
                    PrivilegeError.ExecutionFailed(command, exited, stderr.trim())
                )
            }
        } catch (e: Exception) {
            PrivilegeResult.Failure(
                PrivilegeError.ProviderError("Root", e.message ?: "unknown error")
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
            PrivilegeError.NotSupported("pushFile via root shell (use adb push or Shizuku)", level)
        )
    }

    override fun readFile(devicePath: String): PrivilegeResult {
        return exec("cat $devicePath")
    }

    override fun listDir(devicePath: String): PrivilegeResult {
        return exec("ls -1 $devicePath")
    }

    override fun close() {
        cachedSuPath = null
        cachedAvailable = null
        cachedRootError = null
    }

    companion object {
        private val SU_CANDIDATES = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
        )
    }
}
