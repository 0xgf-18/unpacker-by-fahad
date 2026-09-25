package com.dpt.unpack.ark

import java.io.File
import java.util.concurrent.TimeUnit

/**
 * In-memory dex dump backend for ArkShell-like shells that decrypt their real
 * dex into RAM (InMemoryDexClassLoader / ART AnonymousDexFile) and never write
 * ark_payload_*.dex to disk. Works by attaching frida-dexdump to the live app
 * process and scanning the process heap for dex images.
 *
 * Supports multiple dump strategies (research: T04, T05, T06):
 *  - FRIDA_DEXDUMP: Original frida-dexdump approach (heap scanning)
 *  - CLASSLOADER_HOOK: Hook DexClassLoader/PathClassLoader/InMemoryDexClassLoader
 *  - MEMORY_SCAN: Scan /proc/pid/maps for DEX headers
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

    /** Dump strategies available for different packer types. */
    enum class DumpStrategy {
        FRIDA_DEXDUMP,
        CLASSLOADER_HOOK,
        MEMORY_SCAN,
    }

    /** Boot-classpath jars that the deep scan captures but are NOT app payload. */
    private val BOOT_CLASS_PREFIXES = listOf(
        "android.", "com.android.", "java.", "javax.", "javacard.", "jdk.", "sun.",
        "dalvik.", "libcore.", "kotlin.", "kotlinx.", "org.jetbrains.", "org.intellij.",
        "org.json.", "org.w3c.", "org.xmlpull.", "org.ccil.", "org.apache.harmony.",
        "org.apache.http.", "org.conscrypt.", "org.bouncycastle.",
    )

    private const val D = "$" // Dollar sign shorthand for Frida scripts

    /** ClassLoader hooking script for intercepting DEX loading (research: T05). */
    private val CLASSLOADER_HOOK_SCRIPT: String by lazy {
        val d = D
        """
Java.perform(function() {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
    var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");

    var dexIndex = 0;
    var outputDir = "/data/local/tmp/frida_dumps";

    function ensureDir(dir) {
        var Runtime = Java.use("java.lang.Runtime");
        var runtime = Runtime.getRuntime();
        runtime.exec("mkdir -p " + dir);
    }

    function dumpDex(path, dexBytes) {
        ensureDir(outputDir);
        var outFile = outputDir + "/dump_" + dexIndex + ".dex";
        dexIndex++;
        var File = Java.use("java.io.File");
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        var file = File.${d}new(outFile);
        var fos = FileOutputStream.${d}new(file);
        fos.write(dexBytes);
        fos.close();
        send({type: "dex_dumped", path: outFile, size: dexBytes.length});
    }

    DexClassLoader.${d}init.implementation = function(dexPath, optimizedDir, librarySearchPath, parent) {
        send({type: "dex_loading", method: "DexClassLoader", path: dexPath});
        try {
            var File = Java.use("java.io.File");
            var file = File.${d}new(dexPath);
            if (file.exists()) {
                var fis = Java.use("java.io.FileInputStream").${d}new(file);
                var bytes = [];
                var buf = [];
                while ((buf = fis.read()) !== -1) {
                    bytes.push(buf);
                }
                fis.close();
                var byteArray = new Uint8Array(bytes);
                if (byteArray.length > 0 && byteArray[0] === 0x64 && byteArray[1] === 0x65 &&
                    byteArray[2] === 0x78 && byteArray[3] === 0x0a) {
                    dumpDex(dexPath, byteArray);
                }
            }
        } catch(e) {}
        return this.${d}init(dexPath, optimizedDir, librarySearchPath, parent);
    };

    PathClassLoader.${d}init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function(dexPath, parent) {
        send({type: "dex_loading", method: "PathClassLoader", path: dexPath});
        try {
            var File = Java.use("java.io.File");
            var file = File.${d}new(dexPath);
            if (file.exists()) {
                var fis = Java.use("java.io.FileInputStream").${d}new(file);
                var bytes = [];
                var buf = [];
                while ((buf = fis.read()) !== -1) {
                    bytes.push(buf);
                }
                fis.close();
                var byteArray = new Uint8Array(bytes);
                if (byteArray.length > 0 && byteArray[0] === 0x64 && byteArray[1] === 0x65 &&
                    byteArray[2] === 0x78 && byteArray[3] === 0x0a) {
                    dumpDex(dexPath, byteArray);
                }
            }
        } catch(e) {}
        return this.${d}init(dexPath, parent);
    };

    InMemoryDexClassLoader.${d}init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function(dexBuffer, parent) {
        send({type: "dex_loading", method: "InMemoryDexClassLoader", path: "memory"});
        try {
            var bytes = [];
            var buf = [];
            while (dexBuffer.hasRemaining()) {
                buf = dexBuffer.get();
                bytes.push(buf & 0xFF);
            }
            dexBuffer.rewind();
            var byteArray = new Uint8Array(bytes);
            if (byteArray.length > 0 && byteArray[0] === 0x64 && byteArray[1] === 0x65 &&
                byteArray[2] === 0x78 && byteArray[3] === 0x0a) {
                dumpDex("memory_buffer", byteArray);
            }
        } catch(e) {}
        return this.${d}init(dexBuffer, parent);
    };

    send({type: "classloader_hooks_installed"});
});
""".trimIndent()
    }

    /** Memory scanning script for finding DEX headers in process memory (research: T06). */
    private val MEMORY_SCAN_SCRIPT: String by lazy {
        val d = D
        """
var DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00];
var outputDir = "/data/local/tmp/frida_dumps";
var dexIndex = 0;

function ensureDir(dir) {
    var Runtime = Java.use("java.lang.Runtime");
    var runtime = Runtime.getRuntime();
    runtime.exec("mkdir -p " + dir);
}

function dumpDexAtAddress(address, size) {
    ensureDir(outputDir);
    var outFile = outputDir + "/memscan_" + dexIndex + ".dex";
    dexIndex++;
    try {
        var data = Memory.readByteArray(address, size);
        var File = Java.use("java.io.File");
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        var file = File.${d}new(outFile);
        var fos = FileOutputStream.${d}new(file);
        fos.write(data);
        fos.close();
        send({type: "memscan_dumped", path: outFile, address: address.toString(), size: size});
    } catch(e) {}
}

function scanForDexHeaders() {
    var ranges = Process.enumerateRanges("r--");
    var found = [];
    for (var i = 0; i < ranges.length; i++) {
        var range = ranges[i];
        try {
            for (var offset = 0; offset < range.size - 8; offset += 4096) {
                var base = range.base.add(offset);
                var magic = Memory.readByteArray(base, 8);
                var magicArr = new Uint8Array(magic);
                var match = true;
                for (var j = 0; j < 8; j++) {
                    if (magicArr[j] !== DEX_MAGIC[j]) { match = false; break; }
                }
                if (match) {
                    try {
                        var fileSize = Memory.readU32(base.add(32));
                        if (fileSize > 112 && fileSize < 100 * 1024 * 1024) {
                            var alignedSize = (fileSize + 4095) & ~4095;
                            dumpDexAtAddress(base, Math.min(alignedSize, range.size - offset));
                            found.push({address: base.toString(), size: fileSize});
                        }
                    } catch(e) {}
                }
            }
        } catch(e) {}
    }
    return found;
}

Java.perform(function() {
    send({type: "memory_scan_starting"});
    var results = scanForDexHeaders();
    send({type: "memory_scan_complete", found: results.length, details: results});
});
""".trimIndent()
    }

    /**
     * Dumps every unique dex image found in the target process memory.
     * Supports multiple strategies for different packer types.
     */
    fun dumpInMemory(
        device: ArkDevice,
        deviceType: String,
        adbPath: String?,
        pkg: String,
        timeoutSec: Int,
        host: String = DEFAULT_HOST,
        python: String? = null,
        strategy: DumpStrategy = DumpStrategy.FRIDA_DEXDUMP,
    ): List<DumpPayload> {
        return when (strategy) {
            DumpStrategy.FRIDA_DEXDUMP -> dumpViaFridaDexdump(device, deviceType, adbPath, pkg, timeoutSec, host, python)
            DumpStrategy.CLASSLOADER_HOOK -> dumpViaClassLoaderHook(device, deviceType, adbPath, pkg, timeoutSec, host)
            DumpStrategy.MEMORY_SCAN -> dumpViaMemoryScan(device, deviceType, adbPath, pkg, timeoutSec, host)
        }
    }

    /**
     * Strategy 1: Original frida-dexdump approach (heap scanning).
     */
    private fun dumpViaFridaDexdump(
        device: ArkDevice,
        deviceType: String,
        adbPath: String?,
        pkg: String,
        timeoutSec: Int,
        host: String,
        python: String?,
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
     * Strategy 2: ClassLoader hooking for intercepting DEX loading (research: T05).
     * Hooks DexClassLoader, PathClassLoader, and InMemoryDexClassLoader to capture
     * DEX files as they are loaded by the packer.
     */
    private fun dumpViaClassLoaderHook(
        device: ArkDevice,
        deviceType: String,
        adbPath: String?,
        pkg: String,
        timeoutSec: Int,
        host: String,
    ): List<DumpPayload> {
        if (deviceType == "adb") forwardFridaPort(adbPath)
        val pid = resolvePid(device, pkg)
        val tmp = File.createTempFile("classloader_hook", ".d")
        if (tmp.exists()) tmp.delete()
        tmp.mkdirs()
        try {
            // Write hook script to temp file
            val scriptFile = File(tmp, "hook.js")
            scriptFile.writeText(CLASSLOADER_HOOK_SCRIPT)

            // Use frida to inject the hook script
            val fridaCmd = resolveFridaPath() ?: throw IllegalStateException("frida not found in PATH")
            val args = listOf(
                fridaCmd, "-H", host, "-p", pid,
                "-l", scriptFile.absolutePath,
                "--no-pause"
            )
            val pb = ProcessBuilder(args)
            pb.redirectErrorStream(true)
            val proc = pb.start()

            // Wait for script to install hooks, then trigger app activity
            Thread.sleep(3000)
            device.shell("am start -n $pkg/.MainActivity 2>/dev/null || true")
            Thread.sleep(timeoutSec * 1000L / 2)

            proc.destroyForcibly()

            // Read dumped DEX files
            val deviceTmp = "/data/local/tmp/frida_dumps"
            device.shell("ls $deviceTmp/*.dex 2>/dev/null || true")
            val lsOutput = device.shell("ls $deviceTmp/ 2>/dev/null || true").text
            val dexFiles = lsOutput.lines().filter { it.endsWith(".dex") }

            val payloads = mutableListOf<DumpPayload>()
            for (dexFile in dexFiles) {
                val pullResult = device.shell("cat $deviceTmp/$dexFile")
                val bytes = pullResult.text.toByteArray(Charsets.ISO_8859_1)
                if (bytes.size >= MIN_DEX_BYTES) {
                    payloads.add(DumpPayload(dexFile, bytes))
                }
            }

            // Cleanup device
            device.shell("rm -rf $deviceTmp")

            return deduplicateDexes(payloads)
        } finally {
            tmp.deleteRecursively()
        }
    }

    /**
     * Strategy 3: Memory scanning for DEX headers (research: T06).
     * Scans /proc/pid/maps for DEX magic bytes in memory regions.
     */
    private fun dumpViaMemoryScan(
        device: ArkDevice,
        deviceType: String,
        adbPath: String?,
        pkg: String,
        timeoutSec: Int,
        host: String,
    ): List<DumpPayload> {
        if (deviceType == "adb") forwardFridaPort(adbPath)
        val pid = resolvePid(device, pkg)
        val tmp = File.createTempFile("memory_scan", ".d")
        if (tmp.exists()) tmp.delete()
        tmp.mkdirs()
        try {
            // Write scan script to temp file
            val scriptFile = File(tmp, "scan.js")
            scriptFile.writeText(MEMORY_SCAN_SCRIPT)

            // Use frida to inject the scan script
            val fridaCmd = resolveFridaPath() ?: throw IllegalStateException("frida not found in PATH")
            val args = listOf(
                fridaCmd, "-H", host, "-p", pid,
                "-l", scriptFile.absolutePath,
                "--no-pause"
            )
            val pb = ProcessBuilder(args)
            pb.redirectErrorStream(true)
            val proc = pb.start()

            // Wait for scan to complete
            Thread.sleep(timeoutSec * 1000L / 2)
            proc.destroyForcibly()

            // Read dumped DEX files
            val deviceTmp = "/data/local/tmp/frida_dumps"
            val lsOutput = device.shell("ls $deviceTmp/ 2>/dev/null || true").text
            val dexFiles = lsOutput.lines().filter { it.endsWith(".dex") }

            val payloads = mutableListOf<DumpPayload>()
            for (dexFile in dexFiles) {
                val pullResult = device.shell("cat $deviceTmp/$dexFile")
                val bytes = pullResult.text.toByteArray(Charsets.ISO_8859_1)
                if (bytes.size >= MIN_DEX_BYTES) {
                    payloads.add(DumpPayload(dexFile, bytes))
                }
            }

            // Cleanup device
            device.shell("rm -rf $deviceTmp")

            return deduplicateDexes(payloads)
        } finally {
            tmp.deleteRecursively()
        }
    }

    /** Resolves frida binary path from PATH. */
    private fun resolveFridaPath(): String? {
        val path = System.getenv("PATH") ?: return null
        val sep = if (System.getProperty("os.name").lowercase().contains("win")) ";" else ":"
        for (dir in path.split(sep)) {
            val frida = File(dir, "frida")
            if (frida.exists() && frida.canExecute()) return frida.absolutePath
            val fridaExe = File(dir, "frida.exe")
            if (fridaExe.exists() && fridaExe.canExecute()) return fridaExe.absolutePath
        }
        return null
    }

    /** Deduplicates DEX dumps by defined class set, keeping largest per set. */
    private fun deduplicateDexes(payloads: List<DumpPayload>): List<DumpPayload> {
        if (payloads.isEmpty()) return emptyList()
        val byClasses = LinkedHashMap<Set<String>, DumpPayload>()
        for (p in payloads) {
            val key = runCatching { ArkDexTools.definedClasses(p.bytes).toSet() }
                .getOrNull()?.takeIf { it.isNotEmpty() } ?: setOf(p.name)
            if (isBootOnly(key)) continue
            val prev = byClasses[key]
            if (prev == null || p.bytes.size > prev.bytes.size) {
                byClasses[key] = p
            }
        }
        if (byClasses.isEmpty()) {
            throw IllegalStateException("no useful dex images found via memory scan")
        }
        return byClasses.values.toList()
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