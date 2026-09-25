package com.dpt.unpack.lsp

import java.io.File

/** A resolved apktool launcher: either a jar to run via `java -jar` or a command on PATH. */
sealed class ApktoolRef {
    class Jar(val jar: File) : ApktoolRef()
    class Command(val cmd: File) : ApktoolRef()
}

/**
 * Locates apktool and runs `d`/`b` for the smali round trip.
 * Discovery order: $DPT_APKTOOL_JAR, `apktool.jar` next to the running tool,
 * cwd `apktool.jar`, then `apktool`/`apktool.bat` on PATH.
 *
 * On Android, set [dalvikvmJarDir] to the directory containing `apktool.jar`
 * (typically `context.filesDir`).  `runApktool` will then execute via
 * `dalvikvm -cp <dir>/apktool.jar` instead of `java -jar`.
 */
object ExternalTool {

    /**
     * When non-null, `runApktool` executes via `dalvikvm -cp` using this
     * directory as the classpath root (expects `apktool.jar` inside).
     * Set this from the Android app before calling any LSParanoid pipeline.
     */
    var dalvikvmJarDir: File? = null

    fun findApktool(): ApktoolRef? {
        System.getenv("DPT_APKTOOL_JAR")?.let { p ->
            File(p).takeIf { it.isFile }?.let { return ApktoolRef.Jar(it) }
        }
        for (cp in System.getProperty("java.class.path").split(File.pathSeparator)) {
            val dir = File(cp).absoluteFile.parentFile ?: continue
            if (dir.name == "lib") continue
            File(dir, "apktool.jar").takeIf { it.isFile }?.let { return ApktoolRef.Jar(it) }
        }
        File("apktool.jar").absoluteFile.takeIf { it.isFile }?.let { return ApktoolRef.Jar(it) }
        File(System.getenv("APKTOOL_HOME") ?: "", "apktool.jar").takeIf { it.isFile }?.let { return ApktoolRef.Jar(it) }
        // Android: check the configured dalvikvm jar dir
        dalvikvmJarDir?.let { dir ->
            File(dir, "apktool.jar").takeIf { it.isFile }?.let { return ApktoolRef.Jar(it) }
        }
        return findOnPathApktoolCmd()
    }

    private fun findOnPathApktoolCmd(): ApktoolRef.Command? {
        val path = System.getenv("PATH") ?: return null
        val ext = if (System.getProperty("os.name").lowercase().contains("win")) listOf(".bat", ".cmd", ".exe", "") else listOf("")
        for (dir in path.split(File.pathSeparator)) {
            for (e in ext) {
                val f = File(dir, "apktool$e")
                if (f.isFile) return ApktoolRef.Command(f)
            }
        }
        return null
    }

    /** Runs a tool pass (e.g. `d` or `b`) and returns stdout. Throws on non-zero exit. */
    fun runApktool(ref: ApktoolRef, vararg args: String): String {
        // Android dalvikvm path: use dalvikvm instead of java
        dalvikvmJarDir?.let { jarDir ->
            if (ref is ApktoolRef.Jar) {
                val cp = File(jarDir, "apktool.jar").absolutePath
                // apktool's main class is at org.xmlpull.all[a].Main but the
                // canonical entry is brut.apktool.Main.  We use -jar which is
                // the same as java -jar; dalvikvm supports it.
                val cmd = listOf("dalvikvm", "-cp", cp, "-jar", ref.jar.absolutePath) + args.toList()
                return runProcess(cmd.toTypedArray())
            }
        }
        val java = File(File(System.getProperty("java.home"), "bin"), if (isWin()) "java.exe" else "java")
            .takeIf { it.isFile }
            ?: throw IllegalStateException("java not found in ${System.getProperty("java.home")}/bin")
        val cmd = when (ref) {
            is ApktoolRef.Jar -> listOf(java.absolutePath, "-jar", ref.jar.absolutePath)
            is ApktoolRef.Command -> listOf(ref.cmd.absolutePath)
        }
        return runProcess((cmd + args).toTypedArray())
    }

    private fun runProcess(cmd: Array<String>): String {
        val pb = ProcessBuilder(*cmd)
        pb.redirectErrorStream(true)
        val proc = pb.start()
        val output = proc.inputStream.readBytes().toString(Charsets.UTF_8)
        val code = proc.waitFor()
        if (code != 0) {
            throw IllegalStateException("command failed (exit $code): ${cmd.joinToString(" ")}\n$output")
        }
        return output
    }

    private fun isWin() = System.getProperty("os.name").lowercase().contains("win")
}
