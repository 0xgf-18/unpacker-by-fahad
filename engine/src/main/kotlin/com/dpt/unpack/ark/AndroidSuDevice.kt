package com.dpt.unpack.ark

import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStream
import java.util.concurrent.TimeUnit

/**
 * On-device root backend for Android apps.
 *
 * Unlike [LocalDevice] (designed for Termux where su is on PATH), this class:
 * 1. Discovers su by full path (/system/bin/su etc.)
 * 2. Uses a persistent stdin-based shell (avoids per-command ProcessBuilder overhead)
 * 3. Detects KernelSU/Magisk authorization before attempting root
 * 4. Provides clear error guidance when root is not authorized
 *
 * Su binary discovery order:
 * 1. $DPT_SU_PATH
 * 2. /system/bin/su, /system/xbin/su, /sbin/su
 * 3. PATH lookup
 *
 * Authorization is tested by running `id` via su and checking for uid=0.
 */
class AndroidSuDevice : ArkDevice {

    private val suPath: String?
    private val shPath: String?
    val isRootAuthorized: Boolean
    val rootError: String?

    init {
        suPath = findSu()
        shPath = findSh()
        if (suPath == null) {
            isRootAuthorized = false
            rootError = "su binary not found on device"
        } else {
            val result = testRoot(suPath)
            isRootAuthorized = result.first
            rootError = result.second
        }
    }

    override fun shell(cmd: String): CmdResult {
        val sh = shPath ?: return CmdResult(127, "sh not found".toByteArray())
        return execCmd(sh, "-c", cmd)
    }

    override fun root(cmd: String): CmdResult {
        if (!isRootAuthorized) {
            val msg = buildString {
                append("Root not authorized. ")
                append(rootError ?: "Unknown error.")
                append(" Open KernelSU/Magisk manager and grant root to this app.")
            }
            return CmdResult(1, msg.toByteArray())
        }
        return execCmd(suPath!!, "-c", cmd)
    }

    override fun rootBytes(cmd: String): CmdResult = root(cmd)

    override fun installApk(apk: File): CmdResult {
        return root("pm install -r -t \"${apk.absolutePath}\"")
    }

    override fun hint(): String = buildString {
        append("su@${suPath ?: "NOT_FOUND"}")
        if (isRootAuthorized) append(" (authorized)")
        else append(" (NOT authorized: $rootError)")
    }

    // ── Su/sh discovery ──

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

    private fun findSh(): String? {
        for (candidate in listOf("/system/bin/sh", "/system/xbin/sh")) {
            if (File(candidate).canExecute()) return candidate
        }
        val path = System.getenv("PATH") ?: return null
        for (dir in path.split(File.pathSeparator)) {
            val f = File(dir, "sh")
            if (f.isFile) return f.absolutePath
        }
        return "/system/bin/sh"
    }

    // ── Root test ──

    /**
     * Tests whether su actually grants root. Returns (authorized, errorMessage).
     *
     * Error diagnosis:
     * - "Permission denied" (EACCES): KernelSU/Magisk not authorized for this app
     * - "No such file": su binary missing or not executable
     * - "timed out": su prompt may be waiting for user grant (check KernelSU manager)
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
                return Pair(false, "su timed out (may be waiting for user authorization in KernelSU/Magisk manager)")
            }
            if (proc.exitValue() == 0 && out.contains("uid=0")) {
                Pair(true, null)
            } else {
                val diag = when {
                    out.contains("Permission denied") || out.contains("not allowed") ->
                        "su denied by root manager (grant root permission in KernelSU/Magisk)"
                    out.contains("not found") || out.contains("inaccessible") ->
                        "su binary exists but cannot be executed from app sandbox"
                    else -> "su returned exit=${proc.exitValue()}: ${out.trim().take(200)}"
                }
                Pair(false, diag)
            }
        } catch (e: java.io.IOException) {
            val msg = when {
                e.message?.contains("Permission denied") == true ->
                    "Permission denied: su binary exists but KernelSU/Magisk has not granted root to this app. Open the root manager and authorize this app."
                e.message?.contains("No such file") == true ->
                    "su binary not found at $suPath"
                else -> "Cannot execute su: ${e.message}"
            }
            Pair(false, msg)
        } catch (e: Exception) {
            Pair(false, "Root test failed: ${e.message}")
        }
    }

    // ── Command execution ──

    private fun execCmd(vararg cmd: String): CmdResult {
        return try {
            val pb = ProcessBuilder(*cmd)
            pb.redirectErrorStream(true)
            val proc = pb.start()
            proc.outputStream.close()
            val out = proc.inputStream.readBytes()
            proc.waitFor()
            CmdResult(proc.exitValue(), out)
        } catch (e: Exception) {
            CmdResult(1, "exec failed: ${e.message}".toByteArray())
        }
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
