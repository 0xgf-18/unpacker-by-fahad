package com.dpt.unpack.lsp

import java.io.File

/**
 * Kotlin port of `lsparanoid-deobfuscate.py`.
 *
 * Resolves every
 * `Lorg/lsposed/lsparanoid/DeobfuscatorHelper;->getString(J[Ljava/lang/String;)Ljava/lang/String;`
 * call site in an apktool-decoded smali tree into a literal `const-string`, then optionally
 * strips the LSParanoid runtime, the encrypted chunk construction, and dead decoy methods.
 */
object SmaliDeobfuscator {

    // ---- accumulated tag values stored in registers --------------------------------------
    private class ArrayRef(val key: String)
    private class StringVal(val units: List<Int>)

    private val RE_CONST = Regex("^const(?:/4|/16|/high16|/32)?\\s+(v\\d+|p\\d+),\\s*(-?0x[0-9a-fA-F]+|-?\\d+)(?:L)?$")
    private val RE_CONSTWIDE = Regex("^const-wide(?:/high16|/32)?\\s+(v\\d+|p\\d+),\\s*(-?0x[0-9a-fA-F]+|-?\\d+)(?:L)?$")
    private val RE_CONSTSTR = Regex("^const-string(?:/jumbo)?\\s+(v\\d+|p\\d+),\\s*\"(.*)\"\\s*$")
    private val RE_SGET = Regex("^sget-object\\s+(v\\d+|p\\d+),\\s*(L[\\w/$.;]+)->([A-Za-z0-9_]+):\\[Ljava/lang/String;")
    private val RE_SPUT = Regex("^sput-object\\s+(v\\d+|p\\d+),\\s*(L[\\w/$.;]+)->([A-Za-z0-9_]+):\\[Ljava/lang/String;")
    private val RE_NEWARR = Regex("^new-array\\s+(v\\d+|p\\d+),\\s*(v\\d+|p\\d+),\\s*\\[Ljava/lang/String;")
    private val RE_APUT = Regex("^aput-object\\s+(v\\d+|p\\d+),\\s*(v\\d+|p\\d+),\\s*(v\\d+|p\\d+)")
    private val RE_FILLED = Regex("^filled-new-array(?:/range)?\\s*\\{(.+?)\\},\\s*\\[Ljava/lang/String;")
    private val RE_INVOKE_GETSTR = Regex("^invoke-static\\s+\\{.*?\\}\\s*,\\s*Lorg/lsposed/lsparanoid/DeobfuscatorHelper;->getString\\(J\\[Ljava/lang/String;\\)Ljava/lang/String;")
    private val RE_MOVE_RES_OBJ = Regex("^move-result-object\\s+(v\\d+|p\\d+)")
    private val RE_MOVE_WIDE = Regex("^move-wide(?:/from16|/16)?\\s+(v\\d+|p\\d+),\\s*(v\\d+|p\\d+)")

    class Summary(
        val rounds: Int,
        val total: Int,
        val resolved: Int,
        val skipped: Int,
        val errors: Int,
        val arrays: List<String>,
    )

    // ---- literal parsing -------------------------------------------------------------------

    private fun parseLit(value: String): Long {
        var s = value.trim()
        var neg = false
        if (s.startsWith("-")) { neg = true; s = s.substring(1) }
        val v: Long = if (s.startsWith("0x") || s.startsWith("0X")) {
            java.lang.Long.parseUnsignedLong(s.substring(2), 16)
        } else {
            java.lang.Long.parseUnsignedLong(s, 10)
        }
        val r = if (neg) -v else v
        return r and 0xFFFFFFFFL
    }

    private fun parseLongLit(value: String): Long {
        var s = value.trim()
        if (s.endsWith("L") || s.endsWith("l")) s = s.dropLast(1).trim()
        var neg = false
        if (s.startsWith("-")) { neg = true; s = s.substring(1) }
        val v: Long = if (s.startsWith("0x") || s.startsWith("0X")) {
            java.lang.Long.parseUnsignedLong(s.substring(2), 16)
        } else {
            java.lang.Long.parseUnsignedLong(s, 10)
        }
        return if (neg) -v else v
    }

    private fun fieldRef(cls: String, name: String) = "${cls.removeSuffix(";")}->$name"

    private fun classOf(path: File): String? {
        if (!path.isFile) return null
        val m = Regex("^\\s*\\.class\\s+.*?\\s+(L[\\w/$.;]+)\\s*$", RegexOption.MULTILINE)
            .find(path.readText(Charsets.UTF_8))
        return m?.groupValues?.get(1)
    }

    private fun collectFiles(smaliDirs: List<File>): List<File> {
        val out = mutableListOf<File>()
        for (d in smaliDirs) {
            if (d.isDirectory) d.walkTopDown().filter { it.isFile && it.name.endsWith(".smali") }.forEach(out::add)
        }
        out.sortBy { it.path }
        return out
    }

    // ---- register list helpers -------------------------------------------------------------

    private fun expandRegRange(text: String): List<String> {
        val out = mutableListOf<String>()
        for (pr in text.split(",")) {
            val p = pr.trim()
            val mm = Regex("^(v\\d+|p\\d+)\\s+\\.\\.\\s+(v\\d+|p\\d+)$").find(p)
            if (mm != null) {
                val a = mm.groupValues[1]; val b = mm.groupValues[2]
                val na = a.substring(1).toInt(); val nb = b.substring(1).toInt()
                val step = if (nb >= na) 1 else -1
                var n = na
                while (true) {
                    out.add(a[0] + n.toString())
                    if (n == nb) break
                    n += step
                }
            } else {
                out.add(p)
            }
        }
        return out
    }

    private fun regPlusOne(reg: String): String {
        val kind = reg[0]
        val n = reg.substring(1).toInt() + 1
        return "$kind$n"
    }

    private fun findMoveresult(lines: List<String>, start: Int): Pair<Int, String>? {
        var j = start
        while (j < lines.size) {
            val s = lines[j].trim()
            if (s.isEmpty() || s.startsWith("#") || s.startsWith(".line ")
                || s.startsWith(".restart local ") || s.startsWith(".end local ")
                || s.startsWith(".local ") || s.startsWith(".param ") || s.startsWith(".prologue")
            ) {
                j += 1
                continue
            }
            val m = RE_MOVE_RES_OBJ.matchEntire(s)
            if (m != null) return j to m.groupValues[1]
            return null
        }
        return null
    }

    // ---- array resolution ------------------------------------------------------------------

    private fun resolveArrayRef(arrays: Map<String, Any?>, ref: Any?, seenIn: MutableSet<String>? = null): Any? {
        val seen = seenIn ?: mutableSetOf()
        when (ref) {
            is ArrayRef -> return resolveArrayRef(arrays, ref.key, seen)
            is String -> {
                val key = ref.removePrefix("@arr:")
                if (!seen.add(key)) return null
                val value = arrays[key]
                if (value !is List<*>) return null
                if (value.size == 1 && value.first() is String) {
                    return resolveArrayRef(arrays, value.first() as String, seen)
                }
                return resolveArrayRef(arrays, value, seen)
            }
            is List<*> -> {
                val out = mutableListOf<Any>()
                for (x in ref) {
                    when {
                        x is ArrayRef -> {
                            val sub = resolveArrayRef(arrays, x.key, seen)
                            if (sub == null) return null
                            @Suppress("UNCHECKED_CAST")
                            out.addAll(sub as List<Any>)
                        }
                        x is List<*> && x.isNotEmpty() && x.first() is Int -> out.add(x)
                        else -> return null
                    }
                }
                return if (out.isNotEmpty()) out else null
            }
            else -> return null
        }
    }

    private fun deepEquals(a: Any?, b: Any?): Boolean = when {
        a === b || (a == null && b == null) -> true
        a is Long && b is Long -> a == b
        a is ArrayRef -> b is ArrayRef && a.key == b.key
        a is StringVal -> b is StringVal && a.units == b.units
        a is List<*> && b is List<*> ->
            a.size == b.size && a.indices.all { deepEquals(a[it], b[it]) }
        else -> false
    }

    // ---- main entry ------------------------------------------------------------------------

    fun run(workDir: File, cleanup: Boolean): Summary {
        if (!workDir.isDirectory) throw IllegalStateException("work dir not found: ${workDir.path}")
        val smaliDirs = buildList {
            add(File(workDir, "smali"))
            workDir.listFiles()?.filter { it.isDirectory && it.name.startsWith("smali_") && it.name != "smali" }?.let(::addAll)
        }
        if (smaliDirs.none { it.isDirectory }) throw IllegalStateException("no smali directory found in ${workDir.path}")
        return runOnDirs(smaliDirs, cleanup)
    }

    fun runOnDirs(smaliDirs: List<File>, cleanup: Boolean): Summary {
        val files = collectFiles(smaliDirs)
        val arrays = linkedMapOf<String, Any?>()

        // ---- pass 1: literal base chunk arrays (new-array + const-string + aput-object in <clinit>)
        for (p in files) {
            val cls = classOf(p) ?: continue
            val lines = p.readLines()
            val regmap = mutableMapOf<String, Any?>()
            var inMethod = false
            val pending = mutableMapOf<String, MutableList<Any?>>()
            var arrReg: String? = null
            var lastSput: String? = null
            for (raw in lines) {
                val l = raw.trim()
                if (l.startsWith(".method")) {
                    inMethod = l.contains("<clinit>")
                    regmap.clear(); pending.clear(); arrReg = null; lastSput = null
                    continue
                }
                if (l.startsWith(".end method")) {
                    if (inMethod && arrReg != null && pending[arrReg] != null) {
                        val chunks = pending[arrReg]!!
                        if (chunks.isNotEmpty() && chunks.all { it is List<*> }) {
                            arrays[fieldRef(cls, lastSput ?: "")] = chunks
                        }
                    }
                    inMethod = false
                    continue
                }
                if (!inMethod) continue
                val m1 = RE_CONST.matchEntire(l)
                if (m1 != null) { regmap[m1.groupValues[1]] = parseLit(m1.groupValues[2]); continue }
                val m2 = RE_CONSTWIDE.matchEntire(l)
                if (m2 != null) { regmap[m2.groupValues[1]] = parseLongLit(m2.groupValues[2]); continue }
                val m3 = RE_CONSTSTR.matchEntire(l)
                if (m3 != null) { regmap[m3.groupValues[1]] = LsparanoidCrypto.smaliToUnits(m3.groupValues[2]); continue }
                val m4 = RE_NEWARR.matchEntire(l)
                if (m4 != null) {
                    val size = regmap[m4.groupValues[2]]
                    if (size is Long) {
                        arrReg = m4.groupValues[1]
                        pending[arrReg!!] = MutableList(size.toInt()) { null }
                    }
                    continue
                }
                val m5 = RE_APUT.matchEntire(l)
                if (m5 != null && pending.containsKey(m5.groupValues[2])) {
                    val idx = regmap[m5.groupValues[3]]
                    val value = regmap[m5.groupValues[1]]
                    if (idx is Long && value is List<*> && idx.toInt() in pending[m5.groupValues[2]]!!.indices) {
                        pending[m5.groupValues[2]]!![idx.toInt()] = value
                    }
                    continue
                }
                val m6 = RE_SPUT.matchEntire(l)
                if (m6 != null) { lastSput = m6.groupValues[3]; continue }
            }
        }

        // ---- pass 2: iterative resolution (also discovers derived arrays like q)
        var progress = true
        var rounds = 0
        while (progress && rounds < 30) {
            rounds += 1
            progress = false
            for (p in files) {
                val cls = classOf(p) ?: continue
                val lines = p.readLines()
                val regmap = mutableMapOf<String, Any?>()
                var snapshot: Map<String, Any?>? = null
                var inSwitch = false
                var i = 0
                while (i < lines.size) {
                    val l = lines[i].trim()
                    if (l.startsWith(".method")) { regmap.clear(); snapshot = null; inSwitch = false; i += 1; continue }
                    if (l.startsWith("return") || l.startsWith("throw ")) {
                        if (snapshot != null) { regmap.clear(); regmap.putAll(snapshot!!) }
                        i += 1; continue
                    }
                    if (l.startsWith("packed-switch") || l.startsWith("sparse-switch")) {
                        inSwitch = true; snapshot = HashMap(regmap); i += 1; continue
                    }
                    if (l.startsWith("if-")) {
                        if (!inSwitch) snapshot = HashMap(regmap)
                        i += 1; continue
                    }
                    val m1 = RE_CONST.matchEntire(l)
                    if (m1 != null) { regmap[m1.groupValues[1]] = parseLit(m1.groupValues[2]); i += 1; continue }
                    val m2 = RE_CONSTWIDE.matchEntire(l)
                    if (m2 != null) { regmap[m2.groupValues[1]] = parseLongLit(m2.groupValues[2]); i += 1; continue }
                    val m3 = RE_CONSTSTR.matchEntire(l)
                    if (m3 != null) { regmap[m3.groupValues[1]] = LsparanoidCrypto.smaliToUnits(m3.groupValues[2]); i += 1; continue }
                    val mw = RE_MOVE_WIDE.matchEntire(l)
                    if (mw != null) {
                        val dst = mw.groupValues[1]; val src = mw.groupValues[2]
                        regmap[dst] = regmap[src]
                        regmap[regPlusOne(dst)] = regmap[regPlusOne(src)]
                        i += 1; continue
                    }
                    val ms = RE_SGET.matchEntire(l)
                    if (ms != null) { regmap[ms.groupValues[1]] = ArrayRef(fieldRef(ms.groupValues[2], ms.groupValues[3])); i += 1; continue }
                    val mi = RE_INVOKE_GETSTR.matchEntire(l)
                    if (mi != null) {
                        val regs = Regex("v\\d+|p\\d+").findAll(l).map { it.value }.toList()
                        if (regs.size == 3) {
                            val idVal = regmap[regs[0]]
                            val chunks = resolveArrayRef(arrays, regmap[regs[2]])
                            if (idVal is Long && chunks != null) {
                                try {
                                    @Suppress("UNCHECKED_CAST")
                                    val s = LsparanoidCrypto.getString(idVal, (chunks as List<Any>).map { it as List<Int> })
                                    val fm = findMoveresult(lines, i + 1)
                                    if (fm != null) {
                                        val (_, dstv) = fm
                                        val cur = regmap[dstv]
                                        if (!(cur is ArrayRef)) regmap[dstv] = StringVal(s)
                                        i = fm.first + 1
                                        continue
                                    }
                                } catch (_: Exception) {
                                    // stays unresolved this round
                                }
                            }
                        }
                        i += 1; continue
                    }
                    val mf = RE_FILLED.matchEntire(l)
                    if (mf != null) {
                        val regs = expandRegRange(mf.groupValues[1])
                        val vals = mutableListOf<Any>()
                        var ok = true
                        for (r in regs) {
                            val v = regmap[r]
                            when {
                                v is ArrayRef -> vals.add(ArrayRef(v.key))
                                v is StringVal -> vals.add(v.units)
                                v is List<*> -> vals.add(v.toList())
                                else -> { ok = false; break }
                            }
                        }
                        if (ok) {
                            val fm = findMoveresult(lines, i + 1)
                            if (fm != null) {
                                regmap[fm.second] = vals
                                i = fm.first + 1
                                continue
                            }
                        }
                        i += 1; continue
                    }
                    val ms2 = RE_SPUT.matchEntire(l)
                    if (ms2 != null) {
                        val v = regmap[ms2.groupValues[1]]
                        if (v is List<*> && ms2.groupValues[2] == cls && v.isNotEmpty()) {
                            val allOk = v.all { x ->
                                (x is List<*> && x.isNotEmpty() && x.first() is Int) || x is ArrayRef
                            }
                            if (allOk) {
                                val key = fieldRef(cls, ms2.groupValues[3])
                                if (!deepEquals(arrays[key], v)) {
                                    arrays[key] = v
                                    progress = true
                                }
                            }
                        }
                        i += 1; continue
                    }
                    i += 1
                }
            }
        }

        // ---- final rewrite pass
        var total = 0; var resolved = 0; var skipped = 0; var errors = 0
        val edits = mutableMapOf<String, MutableList<Triple<Int, String, String>>>()
        for (p in files) {
            val cls = classOf(p) ?: continue
            val lines = p.readLines()
            val regmap = mutableMapOf<String, Any?>()
            var snapshot: Map<String, Any?>? = null
            var inSwitch = false
            val fileEdits = mutableListOf<Triple<Int, String, String>>()
            var i = 0
            while (i < lines.size) {
                val l = lines[i].trim()
                if (l.startsWith(".method")) { regmap.clear(); snapshot = null; inSwitch = false; i += 1; continue }
                if (l.startsWith("return") || l.startsWith("throw ")) {
                    if (snapshot != null) { regmap.clear(); regmap.putAll(snapshot!!) }
                    i += 1; continue
                }
                if (l.startsWith("packed-switch") || l.startsWith("sparse-switch")) {
                    inSwitch = true; snapshot = HashMap(regmap); i += 1; continue
                }
                if (l.startsWith("if-")) {
                    if (!inSwitch) snapshot = HashMap(regmap)
                    i += 1; continue
                }
                val m1 = RE_CONST.matchEntire(l)
                if (m1 != null) { regmap[m1.groupValues[1]] = parseLit(m1.groupValues[2]); i += 1; continue }
                val m2 = RE_CONSTWIDE.matchEntire(l)
                if (m2 != null) { regmap[m2.groupValues[1]] = parseLongLit(m2.groupValues[2]); i += 1; continue }
                val m3 = RE_CONSTSTR.matchEntire(l)
                if (m3 != null) { regmap[m3.groupValues[1]] = LsparanoidCrypto.smaliToUnits(m3.groupValues[2]); i += 1; continue }
                val mw = RE_MOVE_WIDE.matchEntire(l)
                if (mw != null) {
                    val dst = mw.groupValues[1]; val src = mw.groupValues[2]
                    regmap[dst] = regmap[src]
                    regmap[regPlusOne(dst)] = regmap[regPlusOne(src)]
                    i += 1; continue
                }
                val ms = RE_SGET.matchEntire(l)
                if (ms != null) { regmap[ms.groupValues[1]] = ArrayRef(fieldRef(ms.groupValues[2], ms.groupValues[3])); i += 1; continue }
                val mi = RE_INVOKE_GETSTR.matchEntire(l)
                if (mi != null) {
                    val regs = Regex("v\\d+|p\\d+").findAll(l).map { it.value }.toList()
                    total += 1
                    val idVal = if (regs.size == 3) regmap[regs[0]] else null
                    val arrRef = if (regs.size == 3) regmap[regs[2]] else null
                    val chunks = resolveArrayRef(arrays, arrRef)
                    if (idVal is Long && chunks != null) {
                        var s: List<Int>? = null
                        try {
                            @Suppress("UNCHECKED_CAST")
                            s = LsparanoidCrypto.getString(idVal, (chunks as List<Any>).map { it as List<Int> })
                        } catch (_: Exception) {
                            errors += 1; i += 1; continue
                        }
                        resolved += 1
                        val fm = findMoveresult(lines, i + 1)
                        if (fm != null) {
                            val (miIdx, dst) = fm
                            fileEdits.add(Triple(i, "REPLACE", "const-string $dst, \"${LsparanoidCrypto.unitsToSmali(s!!)}\""))
                            fileEdits.add(Triple(miIdx, "REMOVE", ""))
                            val cur = regmap[dst]
                            if (!(cur is ArrayRef)) regmap[dst] = StringVal(s!!)
                            i = miIdx + 1
                            continue
                        } else {
                            fileEdits.add(Triple(i, "COMMENT", "# deobfuscated \"${LsparanoidCrypto.unitsToSmali(s!!)}\""))
                            i += 1
                            continue
                        }
                    }
                    skipped += 1
                    i += 1
                    continue
                }
                i += 1
            }
            if (fileEdits.isNotEmpty()) edits[p.path] = fileEdits
        }

        // ---- write rewrites
        for ((path, elist) in edits) {
            val lines = File(path).readLines()
            val rem = elist.filter { it.second == "REMOVE" }.map { it.first }.toMutableSet()
            val out = mutableListOf<String>()
            for ((idx, line) in lines.withIndex()) {
                if (idx in rem) continue
                val repl = elist.filter { it.first == idx && (it.second == "REPLACE" || it.second == "COMMENT") }.map { it.third }.firstOrNull()
                out.add(if (repl != null) "    $repl" else line)
            }
            File(path).writeText(out.joinToString("\n") + "\n")
        }

        val arraysList = arrays.entries
            .sortedBy { it.key }
            .map { (k, v) ->
                val n = (v as? List<*>)?.size ?: 0
                val head = (v as? List<*>)?.firstOrNull()
                val sample = when (head) {
                    is List<*> -> LsparanoidCrypto.unitsSampleForDisplay(head as List<Int>)
                    else -> ""
                }
                "$k  chunks=$n  head: $sample"
            }

        if (cleanup) doCleanup(smaliDirs, files, arrays)

        return Summary(rounds, total, resolved, skipped, errors, arraysList)
    }

    // ---- cleanup: strip runtime, encrypted chunk construction, and decoy methods -----------

    private fun doCleanup(smaliDirs: List<File>, allFiles: List<File>, arrays: Map<String, Any?>) {
        // 1) delete the LSParanoid runtime directory
        for (d in smaliDirs) {
            val runtime = File(File(d, "org"), "lsposed/lsparanoid")
            if (runtime.isDirectory) {
                runtime.deleteRecursively()
                println("  removed .../smali/org/lsposed/lsparanoid")
            }
        }
        val files = allFiles.filter { it.isFile }

        // 2) find chunk classes: classes whose <clinit> builds a static-final String[] whose
        //    contents include at least one ciphertext-like const-string (dense \uXXXX escapes).
        val chunkFields = mutableMapOf<String, String>() // fieldKey -> class token
        for (p in files) {
            val cls = classOf(p) ?: continue
            val text = p.readText(Charsets.UTF_8)
            if (!text.contains("<clinit>")) continue
            if (!text.contains("new-array") && !text.contains("filled-new-array")) continue
            // locate the static final String[] field build: gather const-strings in clinit
            val clinit = text.substringAfter("<clinit>()V", "").substringBefore(".end method", "")
            val units = clinit.lineSequence().mapNotNull { line ->
                RE_CONSTSTR.matchEntire(line.trim())?.let { m ->
                    runCatching { LsparanoidCrypto.smaliToUnits(m.groupValues[2]) }.getOrNull()
                }
            }.toList()
            if (units.none { isCiphertext(it) }) continue
            // find the static field assigned in this clinit
            val field = clinit.lineSequence().mapNotNull { line ->
                RE_SPUT.matchEntire(line.trim())?.let { m -> m.groupValues[3] }
            }.firstOrNull() ?: continue
            chunkFields[fieldRef(cls, field)] = cls
        }

        for (p in files) {
            val cls = classOf(p) ?: continue
            val chunkKey = chunkFields.entries.firstOrNull { it.value == cls }?.key
            if (chunkKey == null) continue

            // strip the encrypted chunk construction from <clinit> (keep field declaration)
            val lines = p.readLines()
            val out = mutableListOf<String>()
            var i = 0
            while (i < lines.size) {
                val l = lines[i].trim()
                if (l.startsWith(".method static constructor <clinit>()V")) {
                    var j = i
                    while (j < lines.size && !lines[j].trim().startsWith(".end method")) j++
                    if (j < lines.size) {
                        out.add(lines[i])
                        out.add("    .locals 0")
                        out.add("")
                        out.add("    return-void")
                        out.add("")
                        out.add(".end method")
                        i = j + 1
                        continue
                    }
                }
                if (l.startsWith(".method")) {
                    // remove decoy static void methods that only load the chunk field + call getString
                    val body = lines.subList(i, nextEndMethod(lines, i)).joinToString("\n")
                    if (isDecoy(body)) {
                        i = skipMethod(lines, i)
                        continue
                    }
                }
                out.add(lines[i])
                i += 1
            }
            p.writeText(out.joinToString("\n") + "\n")
            println("  cleaned .../smali/${relSmali(p)}")
        }

        // 3) strip dead decoy call sites like `invoke-static {..}, L<chunkcls>;->a(J)V`
        val chunkClasses = chunkFields.values.toSet()
        for (p in files) {
            val lines = p.readLines()
            val kept = lines.filterNot { line ->
                chunkClasses.any { clsTok ->
                    line.trim().matches(Regex("^invoke-static\\s+\\{[^}]*\\},\\s*$clsTok->a\\(J\\)V$"))
                }
            }
            if (kept.size != lines.size) {
                p.writeText(kept.joinToString("\n") + "\n")
                println("  stripped decoy calls in .../smali/${relSmali(p)}")
            }
        }
    }

    private fun relSmali(p: File): String {
        val idx = p.path.lastIndexOf("smali" + File.separator)
        return if (idx >= 0) p.path.substring(idx + 6) else p.name
    }

    private fun isCiphertext(units: List<Int>): Boolean {
        if (units.size <= 64) return false
        val esc = units.count { it !in 0x20..0x7E }
        return esc * 2 >= units.size
    }

    private fun isDecoy(body: String): Boolean {
        val b = body.trim()
        if (!b.contains("J)V")) return false
        val hasSget = b.contains("sget-object")
        val hasGetString = b.contains("DeobfuscatorHelper"); 
        val hasResult = b.contains("move-result-object") || b.contains("move-result-wide") || b.contains("move-result ")
        return hasSget && hasGetString && !hasResult
    }

    private fun nextEndMethod(lines: List<String>, start: Int): Int {
        var j = start
        while (j < lines.size && !lines[j].trim().startsWith(".end method")) j++
        return j
    }

    private fun skipMethod(lines: List<String>, start: Int): Int {
        var j = start
        while (j < lines.size && !lines[j].trim().startsWith(".end method")) j++
        return j + 1
    }
}