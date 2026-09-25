package com.dpt.unpack.tools

import java.io.File

/** A resolved RePairip launcher: a fat jar run via `java -jar`. */
class RePairipRef(val jar: File)

/**
 * Locates and runs the vendored RePairip (PairipProtect deprotector) jar.
 * Discovery order: $DPT_REPAIRIP_JAR, `tools/RePairip.jar` next to the running
 * distribution, cwd `RePairip.jar`, then bare `RePairip.jar` heuristics.
 *
 * Mirrors [com.dpt.unpack.lsp.ExternalTool]: absence degrades to `null` instead
 * of failing the run.
 */
object RePairipTool {

    fun find(): RePairipRef? {
        System.getenv("DPT_REPAIRIP_JAR")?.let { p ->
            File(p).takeIf { it.isFile }?.let { return RePairipRef(it) }
        }
        for (cp in System.getProperty("java.class.path").split(File.pathSeparator)) {
            val dir = File(cp).absoluteFile.parentFile ?: continue
            if (dir.name == "lib") continue
            // look next to the jar itself
            File(dir, "RePairip.jar").takeIf { it.isFile }?.let { return RePairipRef(it) }
            // look in tools/ adjacent to the distribution
            File(dir, "tools").takeIf { it.isDirectory }?.let { t ->
                File(t, "RePairip.jar").takeIf { it.isFile }?.let { return RePairipRef(it) }
            }
        }
        // walk up from each classpath entry toward a repo root with tools/RePairip.jar
        for (cp in System.getProperty("java.class.path").split(File.pathSeparator)) {
            var dir: File? = File(cp).absoluteFile.parentFile
            repeat(6) {
                val d = dir ?: return@repeat
                File(d, "tools").takeIf { it.isDirectory }?.let { t ->
                    File(t, "RePairip.jar").takeIf { it.isFile }?.let { return RePairipRef(it) }
                }
                File(d, "RePairip.jar").takeIf { it.isFile }?.let { return RePairipRef(it) }
                dir = d.parentFile
            }
        }
        File("RePairip.jar").absoluteFile.takeIf { it.isFile }?.let { return RePairipRef(it) }
        File("tools", "RePairip.jar").absoluteFile.takeIf { it.isFile }?.let { return RePairipRef(it) }
        return null
    }

    /**
     * Runs a RePairip pass; returns stdout. Throws on non-zero exit.
     *
     * @param input  the APK or .apks bundle
     * @param json   optional captured pairip.json for the static translation patch
     * @param stress merge/log-instrument mode (default; requires -i be an .apks when json==null)
     */
    fun run(ref: RePairipRef, input: File, json: File? = null, lazymod: Boolean = false): String {
        val java = File(File(System.getProperty("java.home"), "bin"), if (isWin()) "java.exe" else "java")
            .takeIf { it.isFile }
            ?: throw IllegalStateException("java not found in ${System.getProperty("java.home")}/bin")
        val args = mutableListOf(java.absolutePath, "-jar", ref.jar.absolutePath, "-i", input.absolutePath)
        if (lazymod) args += "-r"
        if (json != null) args.addAll(listOf("-t", json.absolutePath))
        val pb = ProcessBuilder(args)
        pb.redirectErrorStream(true)
        val proc = pb.start()
        val output = proc.inputStream.readBytes().toString(Charsets.UTF_8)
        val code = proc.waitFor()
        if (code != 0) {
            throw IllegalStateException("RePairip failed (exit $code): ${args.joinToString(" ")}\n$output")
        }
        return output
    }

    private fun isWin() = System.getProperty("os.name").lowercase().contains("win")
}