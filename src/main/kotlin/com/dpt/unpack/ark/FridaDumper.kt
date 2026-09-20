package com.dpt.unpack.ark

import java.io.File
import java.util.concurrent.TimeUnit

/**
 * In-memory dex dump backend for ArkShell-like shells that decrypt their real
 * dex into RAM (InMemoryDexClassLoader / ART AnonymousDexFile) and never write
 * ark_payload_*.dex to disk. Works by attaching frida-dexdump to the live app
 * process and scanning the process heap for dex images.
 *
 * Prerequisites:
 *  - a python interpreter with the 'frida_dexdump' module on the host
 *    (pip install frida-dexdump), and
 *  - frida-server running on the device (default port 27042).
 * For --device adb a `adb forward tcp:27042 tcp:27042` is set up automatically.
 */
object FridaDumper {

    private const val DEFAULT_HOST = "127.0.0.1:27042"
    private const val MIN_DEX_BYTES = 1024

    /** Boot-classpath jars that the deep scan captures but are NOT app payload. */
    private val BOOT_CLASS_PREFIXES = listOf(
        "android.", "com.android.", "java.", "javax.", "javacard.", "jdk.", "sun.",
        "dalvik.", "libcore.", "kotlin.", "kotlinx.", "org.jetbrains.", "org.intellij.",
        "org.json.", "org.w3c.", "org.xmlpull.", "org.ccil.", "org.apache.harmony.",
        "org.apache.http.", "org.conscrypt.", "org.bouncycastle.",
    )

    /** Dumps every unique dex image found in the target process memory. */
    fun dumpInMemory(
        device: ArkDevice,
        deviceType: String,
        adbPath: String?,
        pkg: String,
        timeoutSec: Int,
        host: String = DEFAULT_HOST,
        python: String? = null,
    ): List<DumpPayload> {
        val pyCmd = resolvePython(python)
        if (deviceType == "adb") forwardFridaPort(adbPath)

        val pid = resolvePid(device, pkg)
        val tmp = File.createTempFile("frida_dexdump", ".d")
        if (tmp.exists()) tmp.delete()
        tmp.mkdirs()
        try {
            runDump(pyCmd, host, pid, tmp, timeoutSec)
            return readDexes(tmp)
        } finally {
            tmp.deleteRecursively()
        }
    }

    /**
     * Locates a python interpreter that has the frida_dexdump module.
     * Preference: explicit override, $DPT_PYTHON, py -3, python, python3.
     */
    private fun resolvePython(explicit: String?): List<String> {
        val candidates = listOfNotNull(
            explicit?.split(Regex("\\s+"))?.filter { it.isNotEmpty() }?.takeIf { it.isNotEmpty() },
            System.getenv("DPT_PYTHON")?.split(Regex("\\s+"))?.filter { it.isNotEmpty() }?.takeIf { it.isNotEmpty() },
            listOf("py", "-3"),
            listOf("python"),
            listOf("python3"),
        )
        for (cand in candidates) {
            if (hasDexdumpModule(cand)) return cand
        }
        throw IllegalStateException(
            "no python with 'frida_dexdump' module found - install it (pip install frida-dexdump) " +
                "or point the interpreter via --frida-python / \$DPT_PYTHON"
        )
    }

    private fun hasDexdumpModule(cmd: List<String>): Boolean {
        return try {
            val r = exec(*cmd.toTypedArray(), "-m", "frida_dexdump", "--help")
            r.exit == 0
        } catch (e: Exception) {
            false
        }
    }

    private fun forwardFridaPort(adbPath: String?) {
        val adb = ArkDumper.resolveAdb(adbPath)
        exec(adb.absolutePath, "forward", "--remove-all")
        exec(adb.absolutePath, "forward", "tcp:27042", "tcp:27042")
    }

    private fun resolvePid(device: ArkDevice, pkg: String): String {
        val probe = device.shell("pidof $pkg")
        val pid = probe.text.trim().lines().firstOrNull { it.isNotEmpty() }
            ?: throw IllegalStateException(
                "could not resolve the pid of $pkg (is the app running? frida needs the live process) - " +
                    "launch the app first or drop --no-launch"
            )
        return pid
    }

    private fun runDump(pyCmd: List<String>, host: String, pid: String, out: File, timeoutSec: Int) {
        val args = pyCmd + listOf(
            "-m", "frida_dexdump",
            "-H", host,
            "-p", pid,
            "-o", out.absolutePath,
            "-d", // deep search: scans process memory, catches in-memory dex
        )
        val pb = ProcessBuilder(args)
        pb.redirectErrorStream(true)
        val proc = pb.start()

        val drain = Thread {
            try { proc.inputStream.readBytes() } catch (e: Exception) { /* pipe closed */ }
        }
        drain.isDaemon = true
        drain.start()

        val finished = try {
            proc.waitFor(timeoutSec.toLong(), TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            proc.destroyForcibly()
            throw IllegalStateException("frida-dexdump was interrupted")
        }
        if (!finished) {
            proc.destroyForcibly()
            drain.join(2000)
            throw IllegalStateException("frida-dexdump did not finish within ${timeoutSec}s")
        }
        if (proc.exitValue() != 0) {
            throw IllegalStateException(
                "frida-dexdump exited with code ${proc.exitValue()} - check frida-server is running " +
                    "on the device (default port 27042) and it can attach to $pid"
            )
        }
    }

    /**
     * Reads the dumped dex files, dropping header-fragments and keeping a single
     * representative per unique class set so the rebuilt apk has no duplicate
     * class definitions (in-memory scans produce overlapping captures).
     */
    private fun readDexes(dir: File): List<DumpPayload> {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".dex") }
            ?.sortedBy { dexSortKey(it.name) } ?: emptyList()

        val byClasses = LinkedHashMap<Set<String>, DumpPayload>()
        for (f in files) {
            val raw = runCatching { f.readBytes() }.getOrNull() ?: continue
            if (raw.size < MIN_DEX_BYTES) continue
            val key = runCatching { ArkDexTools.definedClasses(raw).toSet() }
                .getOrNull()?.takeIf { it.isNotEmpty() } ?: setOf(f.name)
            if (isBootOnly(key)) continue // boot-classpath jar swept up by the deep scan, not app payload
            val prev = byClasses[key]
            if (prev == null || raw.size > prev.bytes.size) {
                byClasses[key] = DumpPayload(f.name, raw)
            }
        }
        if (byClasses.isEmpty()) {
            throw IllegalStateException("frida-dexdump finished but found no useful dex images")
        }
        return byClasses.values.toList()
    }

    /** True when every class in the dex belongs to the boot-classpath (framework), not the app. */
    private fun isBootOnly(classes: Set<String>): Boolean =
        classes.isNotEmpty() && classes.all { c -> BOOT_CLASS_PREFIXES.any { c.startsWith(it) } }

    /** classes12.dex -> 12, classes.dex -> 1 (stable ordering). */
    private fun dexSortKey(name: String): Int {
        val m = Regex("classes(\\d*)\\.dex").find(name) ?: return 0
        val n = m.groupValues[1]
        return if (n.isEmpty()) 1 else n.toIntOrNull() ?: 0
    }
}