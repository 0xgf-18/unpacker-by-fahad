package com.dpt.unpack.ark

import java.io.File
import java.nio.charset.StandardCharsets

/** A payload file pulled off the device: original name + raw bytes. */
data class DumpPayload(val name: String, val bytes: ByteArray)

/**
 * Result wrapper of a device command: exit code + merged stdout/stderr bytes.
 * Non-zero exit is not fatal by default here (polling needs that).
 */
data class CmdResult(val exit: Int, val out: ByteArray) {
    val text: String get() = String(out, StandardCharsets.UTF_8)
}

/** Device abstraction: privileged and unprivileged shell access. */
interface ArkDevice {
    fun shell(cmd: String): CmdResult
    fun root(cmd: String): CmdResult
    fun rootBytes(cmd: String): CmdResult
    fun installApk(apk: File): CmdResult
    fun hint(): String
}

object ArkDumper {

    /** Resolves an adb executable from --adb, $ANDROID_HOME/platform-tools or PATH. */
    fun resolveAdb(adbPath: String?): File {
        adbPath?.let { if (File(it).isFile) return File(it) }
        listOfNotNull(
            System.getenv("ANDROID_HOME")?.let { File(it, "platform-tools/adb.exe") },
            System.getenv("ANDROID_HOME")?.let { File(it, "platform-tools/adb") },
        ).forEach { if (it.isFile) return it }
        val path = System.getenv("PATH") ?: ""
        val win = System.getProperty("os.name").lowercase().contains("win")
        for (dir in path.split(File.pathSeparator)) {
            val f = File(dir, if (win) "adb.exe" else "adb")
            if (f.isFile) return f
        }
        throw IllegalStateException("adb not found - pass --adb <path/to/adb> or install platform-tools")
    }

    fun device(deviceType: String, rootMode: String, adbPath: String?): ArkDevice = when (deviceType) {
        "local" -> LocalDevice(rootMode)
        "adb" -> AdbDevice(resolveAdb(adbPath), rootMode)
        else -> throw IllegalStateException("unknown --device '$deviceType' (use adb | local)")
    }

    /**
     * Polls the process's code_cache for the ArkShell payload containers and pulls
     * them, returning files sorted by payload index (ark_payload_0..N).
     */
    fun pullPayloads(device: ArkDevice, pkg: String, timeoutMs: Long): List<DumpPayload> {
        val base = "/data/data/$pkg/code_cache"
        val deadline = System.currentTimeMillis() + timeoutMs
        var paths: List<String> = emptyList()
        while (System.currentTimeMillis() < deadline) {
            val probe = device.root("ls -1 $base/*/ark_payload_*.dex 2>/dev/null; ls -1 $base/ark_payload_*.dex 2>/dev/null")
            val found = probe.text.lines().map { it.trim() }.filter { it.isNotEmpty() && it.endsWith(".dex") }
            if (found.isNotEmpty()) {
                paths = found
                break
            }
            Thread.sleep(1500)
        }
        if (paths.isEmpty()) {
            // last check with a wider net (plain dumped classesN.dex)
            val wide = device.root("ls -1 $base/*/classes*.dex 2>/dev/null; ls -1 $base/classes*.dex 2>/dev/null")
            paths = wide.text.lines().map { it.trim() }.filter { it.isNotEmpty() && it.endsWith(".dex") }
        }
        if (paths.isEmpty()) {
            throw IllegalStateException(
                "no ark_payload dexes appeared under $base after ${timeoutMs / 1000}s - " +
                    "is $pkg really 360-jiagu packed, and did the app actually start? (check --package)"
            )
        }
        return paths.sortedBy { payloadIndex(it) }.map { p ->
            val res = device.rootBytes("cat \"$p\"")
            if (res.out.isEmpty()) throw IllegalStateException(
                "payload decrypts OK but the file is NOT READABLE by this user: $p " +
                    "(SELinux blocks the shell/Shizuku uid from app-private dirs) - " +
                    "use root (--root su on a rooted device), or capture a dump for --dump-dir"
            )
            DumpPayload(p.substringAfterLast('/'), res.out.copyOf())
        }
    }

    /** Parses the trailing integer of names like ark_payload_54.dex (missing -> keep order 0). */
    private fun payloadIndex(path: String): Int {
        val m = Regex("(\\d+)" + "\\.dex$").find(path.substringAfterLast('/'))
        return m?.groupValues?.get(1)?.toIntOrNull() ?: 0
    }
}

/**
 * Direct on-device backend for Termux. Root modes:
 *  - "su":      `su -c '<cmd>'` (rooted device / Magisk)
 *  - "shizuku": `rish -c '<cmd>'` — commands run as the Shizuku server (adb
 *    user, no root needed). rish must be installed on PATH first.
 *  - "auto" (default): use rish when present, otherwise fall back to su.
 */
class LocalDevice(private val rootMode: String) : ArkDevice {

    private val useRish: Boolean = when (rootMode) {
        "shizuku" -> when {
            rishAvailable() -> true
            else -> throw IllegalStateException(
                "rish not found on PATH - install it from Shizuku " +
                    "(\"Use Shizuku in terminal apps\" > Export files), move rish + " +
                    "rish_shizuku.dex into $${'$'}PREFIX/bin, chmod +x, then retry"
            )
        }
        "auto" -> rishAvailable()
        else -> false
    }

    override fun shell(cmd: String) = exec("sh", "-c", cmd)

    override fun root(cmd: String): CmdResult =
        if (useRish) exec("rish", "-c", cmd) else exec("su", "-c", cmd)

    override fun rootBytes(cmd: String): CmdResult =
        if (useRish) exec("rish", "-c", cmd) else exec("su", "-c", cmd)

    override fun installApk(apk: File): CmdResult {
        val pm = "pm install -r -t"
        return if (useRish) {
            // rish does not relay our piped stdin to the child, so install
            // from a temp path that both Termux and the shell uid can reach.
            val parent = apk.absoluteFile.parentFile ?: File(".")
            val tmp = File(parent, ".dpt-install-${System.currentTimeMillis()}.apk")
            tmp.writeBytes(apk.readBytes())
            try {
                exec("rish", "-c", "$pm \"${tmp.absolutePath}\"")
            } finally {
                tmp.delete()
            }
        } else exec("su", "-c", "$pm -", stdin = apk.readBytes())
    }

    override fun hint(): String = when (rootMode) {
        "shizuku" -> "rish -c (Shizuku, no root)"
        "auto" -> if (useRish) "rish -c (auto, Shizuku)" else "su -c (auto, rooted Termux)"
        else -> "su -c (rooted Termux)"
    }

    private fun rishAvailable(): Boolean {
        val path = System.getenv("PATH") ?: return false
        return path.split(File.pathSeparator).any { File(it, "rish").isFile }
    }
}

/**
 * Host backend driving an Android device over adb. Root modes:
 *  - "su":        `adb shell su -c '<cmd>'` (Magisk / generic)
 *  - "bluestacks": BlueStacks' whitelist su only accepts the literal command
 *    `stop`; a helper script named `stop` is pushed to /data/local/tmp and the
 *    caller PATH forces its execution (execvp honors the caller PATH).
 */
class AdbDevice(private val adb: File, rootMode: String) : ArkDevice {

    private val mode = if (rootMode == "auto") "su" else rootMode

    override fun shell(cmd: String) = exec(adb.absolutePath, "shell", cmd)

    override fun root(cmd: String): CmdResult = when (mode) {
        "su" -> exec(adb.absolutePath, "shell", "su -c '$cmd'")
        "bluestacks" -> runBluestacksScript(cmd)
        else -> throw IllegalStateException("unknown --root '$mode' (use su | bluestacks; shizuku is only for --device local)")
    }

    override fun rootBytes(cmd: String): CmdResult = when (mode) {
        "su" -> exec(adb.absolutePath, "shell", "su -c '$cmd'")
        "bluestacks" -> runBluestacksScript(cmd)
        else -> throw IllegalStateException("unknown --root '$mode' (use su | bluestacks; shizuku is only for --device local)")
    }

    override fun installApk(apk: File) = exec(adb.absolutePath, "install", "-r", "-t", apk.absolutePath)

    override fun hint(): String = "adb over ${adb.absolutePath} (root=$mode)"

    private fun runBluestacksScript(cmd: String): CmdResult {
        val tmp = File.createTempFile("dpt_stop", ".sh")
        tmp.writeText("#!/system/bin/sh\nexport PATH=/system/bin:/system/xbin:/data/local/tmp:\$PATH\n$cmd\n")
        try {
            exec(adb.absolutePath, "push", tmp.absolutePath, "/data/local/tmp/stop")
            exec(adb.absolutePath, "shell", "chmod 700 /data/local/tmp/stop")
            return exec(adb.absolutePath, "shell", "PATH=/data/local/tmp:/system/bin:/system/xbin su -c stop")
        } finally {
            tmp.delete()
        }
    }
}

internal fun exec(vararg cmd: String, stdin: ByteArray? = null): CmdResult {
    val pb = ProcessBuilder(*cmd)
    pb.redirectErrorStream(true)
    val proc = pb.start()
    if (stdin != null) {
        try {
            proc.outputStream.use { s -> s.write(stdin) }
        } catch (e: java.io.IOException) {
            proc.destroy()
            proc.waitFor()
            return CmdResult(proc.exitValue(), ("stdin write failed (${e.message}) - the tool can't pipe to this backend").encodeToByteArray())
        }
    } else {
        proc.outputStream.close()
    }
    val out = proc.inputStream.readBytes()
    proc.waitFor()
    return CmdResult(proc.exitValue(), out)
}