package com.dpt.unpack.ark

/**
 * Lightweight dex introspection for the ArkShell pipeline:
 *  - enumerates every class string;
 *  - finds classes whose superclass is android.app.Application (the real app entry);
 *  - narrows candidates using the shell stub dex, which usually still references
 *    the original Application class name as a string.
 */
object ArkDexTools {

    fun definedClasses(dex: ByteArray): List<String> {
        val out = mutableListOf<String>()
        val typeIdsSize = u32(dex, 0x40).toInt()
        val typeIdsOff = u32(dex, 0x44).toInt()
        val classDefsSize = u32(dex, 0x60).toInt()
        val classDefsOff = u32(dex, 0x64).toInt()
        for (i in 0 until classDefsSize) {
            val cd = classDefsOff + i * 32
            if (cd + 32 > dex.size) break
            val typeIdx = u32(dex, cd).toInt()
            if (typeIdx < 0 || typeIdx >= typeIdsSize) continue
            val t = typeIdsOff + typeIdx * 4
            val strIdx = u32(dex, t).toInt()
            readStringAt(dex, u32(dex, stringIdsOff(dex, strIdx)).toInt())?.let { out.add(it) }
        }
        return out
    }

    /** Class names (com/foo/Bar) whose superclass is android.app.Application. */
    fun applicationClasses(dex: ByteArray): List<String> {
        val stringIdsSize = u32(dex, 0x38).toInt()
        val stringIdsOff = u32(dex, 0x3C).toInt()
        val typeIdsSize = u32(dex, 0x40).toInt()
        val typeIdsOff = u32(dex, 0x44).toInt()
        val classDefsSize = u32(dex, 0x60).toInt()
        val classDefsOff = u32(dex, 0x64).toInt()

        fun desc(typeIdx: Int): String? {
            if (typeIdx < 0 || typeIdx >= typeIdsSize) return null
            val t = typeIdsOff + typeIdx * 4
            return readStringAt(dex, u32(dex, stringIdsOff + u32(dex, t).toInt() * 4).toInt())
        }

        val appType = (0 until typeIdsSize).firstOrNull { desc(it) == "Landroid/app/Application;" } ?: return emptyList()

        val result = mutableListOf<String>()
        for (i in 0 until classDefsSize) {
            val cd = classDefsOff + i * 32
            if (cd + 32 > dex.size) break
            if (u32(dex, cd + 8).toInt() != appType) continue
            desc(u32(dex, cd).toInt())?.removePrefix("L")?.removeSuffix(";")?.let { result.add(it) }
        }
        return result
    }

    /**
     * Discovers the real Application class across the recovered payload dexes.
     * Preference: 1) explicit override, 2) candidate also referenced as a string in
     * the shell stub dex, 3) the single distinct candidate, 4) deterministic pick.
     */
    fun discoverRealApplication(stubDex: ByteArray?, payloadDexes: List<ByteArray>, override: String?): String? {
        override?.let { return it }

        val apps = payloadDexes.flatMap { applicationClasses(it) }
            .filter { cls ->
                listOf("b2al", "com.qihoo", "stub", "ark", "android.app", "dpt").none {
                    cls.startsWith(it, ignoreCase = true)
                }
            }
            .distinct()
        if (apps.isEmpty()) return null

        val stubApps = stubDex?.let { allStrings(it) }?.mapNotNull { s ->
            s.removePrefix("L").takeIf { it.endsWith("Application;") }?.removeSuffix(";")
        }?.filter { !it.startsWith("b2al", ignoreCase = true) && !it.startsWith("com.qihoo", ignoreCase = true) }
            ?: emptyList()

        stubApps.firstOrNull { apps.contains(it) }?.let { return it }
        if (apps.size == 1) return apps[0]
        val firstDex = payloadDexes.firstOrNull { d -> applicationClasses(d).any { apps.contains(it) } }
        firstDex?.let { d -> applicationClasses(d).firstOrNull { apps.contains(it) } }?.let { return it }
        return apps.minByOrNull { it.length }
    }

    fun allStrings(dex: ByteArray): List<String> {
        val count = u32(dex, 0x38).toInt()
        return (0 until count).mapNotNull { readStringAt(dex, u32(dex, stringIdsOff(dex, it)).toInt()) }
    }

    private fun stringIdsOff(dex: ByteArray, idx: Int): Int {
        val off = u32(dex, 0x3C).toInt() + idx * 4
        if (off + 4 > dex.size) return 0
        return off
    }

    private fun readStringAt(dex: ByteArray, dataOff: Int): String? {
        var i = dataOff
        if (i < 0 || i >= dex.size) return null
        var charLen = 0
        val first = dex[i].toInt() and 0xFF
        if (first and 0x80 == 0) {
            charLen = first
            i += 1
        } else {
            if (i + 1 >= dex.size) return null
            charLen = ((first and 0x7F) shl 8) or (dex[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (charLen < 0 || i + charLen > dex.size) return null
        return String(dex, i, charLen, Charsets.UTF_8)
    }

    private fun u32(b: ByteArray, o: Int): Long =
        (b[o].toLong() and 0xFF) or ((b[o + 1].toLong() and 0xFF) shl 8) or
            ((b[o + 2].toLong() and 0xFF) shl 16) or ((b[o + 3].toLong() and 0xFF) shl 24)
}