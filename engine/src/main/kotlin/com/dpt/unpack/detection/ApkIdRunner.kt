package com.dpt.unpack.detection

import java.io.File

/** A single APKiD rule hit: which yara rule matched, in which archived file. */
data class ApkIdHit(
    val rule: String,
    val file: String,
    val notes: String,
)

/** Resolved launcher for the optional APKiD process. */
data class ApkIdCommand(
    val argv: List<String>,
    val env: Map<String, String> = emptyMap(),
) {
    override fun toString() = argv.joinToString(" ")
}

/**
 * Optional boosted detector: runs rednaga/APKiD (YARA) when it is available and
 * folds its rule hits into the profile. Like [com.dpt.unpack.lsp.ExternalTool],
 * discovery is graceful -- a missing interpreter or a compile failure (e.g. no
 * MSVC on Windows for yara-python) degrades to `null` instead of failing the run.
 *
 * Discovery order for the launcher:
 * 1. $DPT_APKID_CMD (explicit) -- e.g. a bare `apkid` or `python -m apkid`.
 * 2. `apkid` / `apkid.bat` on PATH.
 * 3. A vendored `tools/apkid` checkout next to the running distribution, invoked
 *    through the `python` / `python3` / `py` interpreter on PATH (or the
 *    interpreter DPT itself was launched with), seeding PYTHONPATH.
 */
object ApkIdRunner {

    private fun isWin() = System.getProperty("os.name").lowercase().contains("win")

    fun find(): ApkIdCommand? {
        System.getenv("DPT_APKID_CMD")?.takeIf { it.isNotBlank() }?.let {
            return ApkIdCommand(it.split(Regex("\\s+")).filter(String::isNotEmpty))
        }
        val path = System.getenv("PATH") ?: return null
        val names = if (isWin()) listOf("apkid.bat", "apkid.cmd", "apkid.exe", "apkid") else listOf("apkid")
        for (dir in path.split(File.pathSeparator)) {
            for (n in names) {
                val f = File(dir, n)
                if (f.isFile) return ApkIdCommand(listOf(f.absolutePath))
            }
        }
        return pythonApkidCmd()
    }

    /** Locates an interpreter + an importable `apkid` package (over PYTHONPATH if vendored). */
    private fun pythonApkidCmd(): ApkIdCommand? {
        val vendored = findVendoredApkid()
        val interps = interpreterCandidates()
        for (i in interps) {
            if (probeApkidModule(i, vendored)) {
                val env = if (vendored != null) mapOf("PYTHONPATH" to vendored.absolutePath) else emptyMap()
                return ApkIdCommand(listOf(i, "-m", "apkid"), env)
            }
        }
        return null
    }

    /** `tools/apkid` checkout next to the running distribution (jar parent dir). */
    private fun findVendoredApkid(): File? {
        System.getProperty("java.class.path").split(File.pathSeparator)
            .mapNotNull { File(it).absoluteFile.parentFile }
            .distinct()
            .forEach { d ->
                for (candidate in listOf(File(d, "tools"))) {
                    val root = File(candidate, "apkid")
                    if (File(root, "apkid").isDirectory) return root
                }
                // bare `tools/apkid` sibling of a single bundled jar.
                val stable = File(d.parentFile ?: d, "tools")
                val root = File(stable, "apkid")
                if (File(root, "apkid").isDirectory) return root
            }
        return null
    }

    /**
     * Candidate interpreters: the one whose dir holds `python.exe` (launched-with),
     * PATH python/py launcher, then generic names.
     */
    private fun interpreterCandidates(): List<String> {
        val out = LinkedHashSet<String>()
        val pythonExe = if (isWin()) "python.exe" else "python"
        System.getProperty("java.class.path").split(File.pathSeparator)
            .mapNotNull { File(it).absoluteFile.parentFile }
            .forEach { d ->
                val cwd = d.parentFile
                listOf(d, File(d, "..").absoluteFile)
                    .forEach { base ->
                        File(base, pythonExe).takeIf { it.isFile }?.let { out.add(it.absolutePath) }
                        File(base, "py.exe").takeIf { it.isFile && isWin() }?.let { out.add(it.absolutePath) }
                    }
                if (cwd != null) File(cwd, pythonExe).takeIf { it.isFile }?.let { out.add(it.absolutePath) }
            }
        System.getenv("PATH")?.split(File.pathSeparator)?.forEach { dir ->
            File(dir, pythonExe).takeIf { it.isFile }?.let { out.add(it.absolutePath) }
            if (isWin()) File(dir, "py.exe").takeIf { it.isFile }?.let { out.add(it.absolutePath) }
        }
        out += listOf("python3", "python")
        return out.toList()
    }

    private fun probeApkidModule(interp: String, vendored: File?): Boolean {
        return try {
            val probe = if (vendored != null) {
                arrayOf("-c", "import sys; sys.path.insert(0, r\"${vendored.absolutePath}\"); import apkid")
            } else {
                arrayOf("-c", "import apkid")
            }
            val pb = ProcessBuilder(interp, *probe)
            pb.redirectErrorStream(true)
            val p = pb.start()
            p.inputStream.readBytes()
            p.waitFor() == 0
        } catch (e: Exception) {
            false
        }
    }

    /** Scans an APK and returns rule hits; null when unavailable or a scan failure. */
    fun scan(apk: File, timeout: Int = 30): List<ApkIdHit>? {
        val cmd = find() ?: return null
        val argv = cmd.argv + listOf("-a", apk.absolutePath, "-j", "-t", timeout.toString())
        val output = try {
            val pb = ProcessBuilder(argv)
            pb.redirectErrorStream(true)
            cmd.env.forEach { (k, v) -> pb.environment()[k] = v }
            val p = pb.start()
            val out = p.inputStream.readBytes().toString(Charsets.UTF_8)
            val code = p.waitFor()
            if (code != 0) return null
            out
        } catch (e: Exception) {
            return null
        }
        return parseHits(output)
    }

    private fun parseHits(json: String): List<ApkIdHit> {
        val hits = mutableListOf<ApkIdHit>()
        val re = Regex(
            "\"filename\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"|" +
                "\"rule\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"|" +
                "\"notes\"\\s*:\\s*\\[((?:[^\\]]|\\\\.)*)\\]"
        )
        var file = ""
        var rule = ""
        val notes = ArrayDeque<String>()
        for (m in re.findAll(json)) {
            val f = m.groupValues[1]
            val r = m.groupValues[2]
            val n = m.groupValues[3]
            when {
                f.isNotEmpty() -> {
                    flush(hits, file, rule, notes)
                    file = f; rule = ""
                }
                r.isNotEmpty() -> {
                    flush(hits, file, rule, notes)
                    rule = r
                }
                n.isNotEmpty() -> Regex("\"((?:[^\"\\\\]|\\\\.)*)\"").findAll(n)
                    .forEach { notes.addLast(it.groupValues[1]) }
            }
        }
        flush(hits, file, rule, notes)
        return hits
    }

    private fun flush(hits: MutableList<ApkIdHit>, file: String, rule: String, notes: ArrayDeque<String>) {
        if (rule.isNotEmpty()) {
            hits += ApkIdHit(rule, file.ifEmpty { "<apk>" }, notes.joinToString("; "))
        }
        notes.clear()
    }
}
