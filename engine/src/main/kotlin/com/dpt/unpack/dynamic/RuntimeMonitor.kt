package com.dpt.unpack.dynamic

import com.dpt.unpack.privilege.PrivilegeProvider
import java.io.File

/**
 * Monitors runtime behavior of a target application.
 *
 * Captures:
 * - Logcat output (filtered by target PID/package)
 * - Process status and memory maps (/proc/<pid>/maps, /proc/<pid>/status)
 * - DEX file descriptors (/proc/<pid>/fd)
 * - Filesystem changes
 *
 * The monitor runs as a background loop and can be stopped at any time.
 */
interface RuntimeMonitor {

    /**
     * Start monitoring the target application.
     *
     * @param packageName the package to monitor
     * @param workspace the workspace to store captured data
     */
    fun start(packageName: String, workspace: AnalysisWorkspace)

    /**
     * Stop monitoring and finalize captured data.
     */
    fun stop()

    /**
     * Check if monitoring is active.
     */
    fun isRunning(): Boolean

    /**
     * Capture a snapshot of the current process state.
     *
     * @param packageName the target package
     * @return snapshot with process info
     */
    fun snapshot(packageName: String): ProcessSnapshot

    /**
     * Get the collected logcat output.
     */
    fun getLogcat(): String

    /**
     * Get captured memory maps for the target process.
     */
    fun getMemoryMaps(packageName: String): String
}

/**
 * Snapshot of a process at a point in time.
 */
data class ProcessSnapshot(
    val pid: Int,
    val packageName: String,
    val status: String = "",
    val memoryMaps: String = "",
    val openFiles: List<String> = emptyList(),
    val dexFiles: List<String> = emptyList(),
    val nativeLibraries: List<String> = emptyList(),
    val timestamp: Long = System.currentTimeMillis(),
)

/**
 * Default implementation using logcat and /proc filesystem.
 */
class DefaultRuntimeMonitor(
    private val provider: PrivilegeProvider,
) : RuntimeMonitor {

    private val tag = "RuntimeMonitor"
    private var logcatProcess: Process? = null
    private var logcatBuffer = StringBuilder()
    @Volatile private var running = false
    private var monitorThread: Thread? = null

    override fun start(packageName: String, workspace: AnalysisWorkspace) {
        if (running) return
        running = true
        logcatBuffer.clear()

        monitorThread = Thread({
            captureLogcat(packageName, workspace)
        }, "dpt-logcat-monitor").apply {
            isDaemon = true
            start()
        }
    }

    override fun stop() {
        running = false
        try { logcatProcess?.destroyForcibly() } catch (_: Exception) {}
        try { monitorThread?.join(3000) } catch (_: Exception) {}
        logcatProcess = null
        monitorThread = null
    }

    override fun isRunning(): Boolean = running

    override fun snapshot(packageName: String): ProcessSnapshot {
        val pid = getPid(packageName)
        if (pid <= 0) {
            return ProcessSnapshot(pid = -1, packageName = packageName, status = "not running")
        }

        val status = provider.exec("cat /proc/$pid/status").let {
            if (it is com.dpt.unpack.privilege.PrivilegeResult.Success) it.output else ""
        }
        val maps = provider.exec("cat /proc/$pid/maps").let {
            if (it is com.dpt.unpack.privilege.PrivilegeResult.Success) it.output else ""
        }
        val fdList = provider.exec("ls -1 /proc/$pid/fd").let {
            if (it is com.dpt.unpack.privilege.PrivilegeResult.Success) {
                it.output.lines().filter { line -> line.isNotBlank() }
            } else emptyList()
        }

        val dexFiles = fdList.mapNotNull { fd ->
            val link = provider.exec("readlink /proc/$pid/fd/$fd")
            if (link is com.dpt.unpack.privilege.PrivilegeResult.Success) {
                val path = link.output.trim()
                if (path.contains(".dex", ignoreCase = true) || path.contains("memfd:", ignoreCase = true)) {
                    path
                } else null
            } else null
        }

        val nativeLibs = fdList.mapNotNull { fd ->
            val link = provider.exec("readlink /proc/$pid/fd/$fd")
            if (link is com.dpt.unpack.privilege.PrivilegeResult.Success) {
                val path = link.output.trim()
                if (path.contains(".so", ignoreCase = true)) path else null
            } else null
        }

        return ProcessSnapshot(
            pid = pid,
            packageName = packageName,
            status = status,
            memoryMaps = maps,
            openFiles = fdList,
            dexFiles = dexFiles,
            nativeLibraries = nativeLibs,
        )
    }

    override fun getLogcat(): String = synchronized(logcatBuffer) {
        logcatBuffer.toString()
    }

    override fun getMemoryMaps(packageName: String): String {
        val pid = getPid(packageName)
        if (pid <= 0) return ""
        return when (val result = provider.exec("cat /proc/$pid/maps")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> result.output
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> ""
        }
    }

    private fun captureLogcat(packageName: String, workspace: AnalysisWorkspace) {
        try {
            provider.exec("logcat -c")
            val process = Runtime.getRuntime().exec(
                arrayOf("sh", "-c", "logcat -v threadtime *:V")
            )
            logcatProcess = process
            val reader = process.inputStream.bufferedReader()
            val pid = getPid(packageName)
            while (running) {
                val line = reader.readLine() ?: break
                if (pid > 0 && line.contains("$pid ")) {
                    synchronized(logcatBuffer) {
                        logcatBuffer.appendLine(line)
                    }
                }
            }
            val logcatFile = workspace.logcatFile()
            logcatFile.writeText(getLogcat())
        } catch (_: Exception) {
            // Monitor thread exiting
        }
    }

    private fun getPid(packageName: String): Int {
        return when (val result = provider.exec("pidof $packageName")) {
            is com.dpt.unpack.privilege.PrivilegeResult.Success -> {
                result.output.trim().split("\\s+".toRegex()).firstOrNull()?.toIntOrNull() ?: -1
            }
            is com.dpt.unpack.privilege.PrivilegeResult.Failure -> -1
        }
    }
}
