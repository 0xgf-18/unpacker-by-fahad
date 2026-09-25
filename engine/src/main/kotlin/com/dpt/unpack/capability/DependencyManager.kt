package com.dpt.unpack.capability

import java.io.File
import java.security.MessageDigest

/**
 * Centralized dependency management for external tools.
 * Detects, validates, and manages tool availability.
 */
object DependencyManager {

    data class ToolInfo(
        val name: String,
        val path: File?,
        val available: Boolean,
        val version: String? = null,
        val reason: String? = null,
        val managedPath: File? = null,
    )

    private var toolsDir: File? = null

    fun initialize(appFilesDir: File) {
        toolsDir = File(appFilesDir, "tools").apply { mkdirs() }
    }

    fun getToolsDir(): File? = toolsDir

    fun checkApkTool(): ToolInfo {
        val managed = toolsDir?.let { File(it, "apktool.jar") }
        if (managed != null && managed.exists() && managed.length() > 1024) {
            val ver = extractApktoolVersion(managed)
            return ToolInfo("apktool", managed, true, ver, managedPath = managed)
        }
        val envJar = System.getenv("DPT_APKTOOL_JAR")?.let { File(it) }
        if (envJar != null && envJar.exists() && envJar.length() > 1024) {
            val ver = extractApktoolVersion(envJar)
            return ToolInfo("apktool", envJar, true, ver, managedPath = null)
        }
        val cwd = File("apktool.jar")
        if (cwd.exists() && cwd.length() > 1024) {
            val ver = extractApktoolVersion(cwd)
            return ToolInfo("apktool", cwd, true, ver)
        }
        val pathCmd = findOnPath("apktool")
        if (pathCmd != null) {
            return ToolInfo("apktool", pathCmd, true, "PATH", managedPath = null)
        }
        return ToolInfo(
            "apktool", null, false, null,
            "apktool.jar not found. Download from https://github.com/iBotPeaches/Apktool/releases " +
                "and place in ${toolsDir?.absolutePath ?: "app files/tools/"}",
        )
    }

    fun checkRePairip(): ToolInfo {
        val managed = toolsDir?.let { File(it, "RePairip.jar") }
        if (managed != null && managed.exists() && managed.length() > 1024) {
            return ToolInfo("RePairip", managed, true, managedPath = managed)
        }
        val envJar = System.getenv("DPT_REPAIRIP_JAR")?.let { File(it) }
        if (envJar != null && envJar.exists() && envJar.length() > 1024) {
            return ToolInfo("RePairip", envJar, true, managedPath = null)
        }
        val cwd = File("RePairip.jar")
        if (cwd.exists() && cwd.length() > 1024) {
            return ToolInfo("RePairip", cwd, true)
        }
        val toolsAdjacent = listOf(
            File("tools/RePairip.jar"),
            File("../tools/RePairip.jar"),
            File("../../tools/RePairip.jar"),
        )
        for (f in toolsAdjacent) {
            if (f.exists() && f.length() > 1024) {
                return ToolInfo("RePairip", f.canonicalFile, true)
            }
        }
        return ToolInfo(
            "RePairip", null, false, null,
            "RePairip.jar not found. This tool is required for PairIPProtect analysis. " +
                "Place in ${toolsDir?.absolutePath ?: "app files/tools/"}",
        )
    }

    fun checkJava(): ToolInfo {
        val javaHome = System.getenv("JAVA_HOME")?.let { File(it) }
        if (javaHome != null) {
            val javaExe = File(javaHome, "bin/java${if (isWindows()) ".exe" else ""}")
            if (javaExe.exists()) return ToolInfo("java", javaExe, true, System.getProperty("java.version"))
        }
        val pathJava = findOnPath("java")
        if (pathJava != null) {
            return ToolInfo("java", pathJava, true, System.getProperty("java.version"))
        }
        return ToolInfo("java", null, false, null, "Java runtime not found")
    }

    fun checkAdb(): ToolInfo {
        val adbHome = System.getenv("ANDROID_HOME")?.let { File(it, "platform-tools/adb${if (isWindows()) ".exe" else ""}") }
        if (adbHome != null && adbHome.exists()) {
            return ToolInfo("adb", adbHome, true)
        }
        val pathAdb = findOnPath("adb")
        if (pathAdb != null) {
            return ToolInfo("adb", pathAdb, true)
        }
        return ToolInfo("adb", null, false, null, "ADB not found in PATH or ANDROID_HOME")
    }

    fun checkFrida(): ToolInfo {
        val pathFrida = findOnPath("frida")
        if (pathFrida != null) {
            return ToolInfo("frida", pathFrida, true)
        }
        return ToolInfo("frida", null, false, null, "Frida not found (optional for dynamic analysis)")
    }

    fun verifyChecksum(file: File, expectedSha256: String): Boolean {
        if (!file.exists()) return false
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            var read: Int
            while (input.read(buffer).also { read = it } != -1) {
                digest.update(buffer, 0, read)
            }
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        return actual.equals(expectedSha256, ignoreCase = true)
    }

    private fun extractApktoolVersion(jar: File): String? {
        return try {
            val proc = ProcessBuilder(listOf("java", "-jar", jar.absolutePath, "--version"))
                .redirectErrorStream(true)
                .start()
            val output = proc.inputStream.bufferedReader().readText().trim()
            proc.waitFor()
            if (output.isNotEmpty()) output.lines().firstOrNull() else null
        } catch (_: Exception) {
            null
        }
    }

    private fun findOnPath(name: String): File? {
        val path = System.getenv("PATH") ?: return null
        val sep = if (isWindows()) ";" else ":"
        val extensions = if (isWindows()) listOf("", ".bat", ".cmd", ".exe") else listOf("")
        for (dir in path.split(sep)) {
            for (ext in extensions) {
                val f = File(dir, "$name$ext")
                if (f.exists() && f.canExecute()) return f
            }
        }
        return null
    }

    private fun isWindows(): Boolean =
        System.getProperty("os.name").lowercase().contains("win")

    fun summary(): List<ToolInfo> = listOf(
        checkJava(),
        checkAdb(),
        checkApkTool(),
        checkRePairip(),
        checkFrida(),
    )
}
