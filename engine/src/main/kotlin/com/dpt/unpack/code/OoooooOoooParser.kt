package com.dpt.unpack.code

import com.dpt.unpack.util.Cursor

data class CodeRecord(val methodIdx: Long, val insns: ByteArray)

data class CodeStoreCandidate(
    val version: Int,
    val dexCount: Int,
    val sections: Map<Int, List<CodeRecord>>,
    val layoutDesc: String,
)

object OoooooOoooParser {

    private const val XOR_KEY = 0x6F
    private const val MAX_CANDIDATES = 24

    fun parseCandidates(data: ByteArray): List<CodeStoreCandidate> {
        if (data.size < 8) return emptyList()
        val c = Cursor(data)
        val version = c.u16()
        val dexCount = c.u16()
        if (dexCount < 1 || dexCount > 64 || 4 + 4 * dexCount > data.size) return emptyList()
        val offsets = IntArray(dexCount)
        for (i in 0 until dexCount) offsets[i] = c.u32().toInt()
        val indexTableSize = 4 + 4 * dexCount

        val ordered = offsets.withIndex()
            .filter { (_, off) -> off >= indexTableSize && off + 2 <= data.size }
            .sortedBy { (_, off) -> off }

        val optionsByDexIndex = LinkedHashMap<Int, List<SectionParse>>()
        for (k in ordered.indices) {
            val (dexIndex, off) = ordered[k]
            val sectionEnd = ordered.getOrNull(k + 1)?.value ?: data.size
            val opts = sectionOptions(data, dexIndex, off, sectionEnd)
            if (opts.isNotEmpty()) optionsByDexIndex[dexIndex] = opts
        }
        if (optionsByDexIndex.isEmpty()) return emptyList()

        var combos = listOf(emptyList<SectionParse>())
        for (dexIndex in optionsByDexIndex.keys) {
            val opts = optionsByDexIndex[dexIndex]!!
            combos = combos.flatMap { prefix -> opts.map { prefix + it } }
            if (combos.size > MAX_CANDIDATES) combos = combos.take(MAX_CANDIDATES)
        }

        return combos.take(MAX_CANDIDATES).map { combo ->
            val layoutDesc = combo.joinToString(",") { "dex${it.dexIndex}:${it.layout}" }
            CodeStoreCandidate(
                version,
                dexCount,
                combo.associate { it.dexIndex to it.records },
                layoutDesc,
            )
        }
    }

    private data class SectionParse(val dexIndex: Int, val layout: String, val records: List<CodeRecord>)

    private fun sectionOptions(data: ByteArray, dexIndex: Int, off: Int, sectionEnd: Int): List<SectionParse> {
        val result = ArrayList<SectionParse>()
        parseLayout(data, off, sectionEnd, sizeFirst = false, xor = false)?.let {
            result.add(SectionParse(dexIndex, "standard", it))
        }
        val marker = markerRatio(data, off, sectionEnd)
        val xor = marker != null && marker >= 0.15
        if (marker == null || xor) {
            parseLayout(data, off, sectionEnd, sizeFirst = true, xor = xor)?.let {
                result.add(SectionParse(dexIndex, if (xor) "size-first+xor" else "size-first", it))
            }
        }
        return result
    }

    private fun parseLayout(
        data: ByteArray,
        off: Int,
        sectionEnd: Int,
        sizeFirst: Boolean,
        xor: Boolean,
    ): List<CodeRecord>? {
        if (sectionEnd - off < 2) return null
        val c = Cursor(data)
        c.seek(off)
        val methodCount = c.u16()
        val records = ArrayList<CodeRecord>(methodCount)
        for (m in 0 until methodCount) {
            if (sectionEnd - c.pos < 8) return null
            val first = c.u32()
            val second = c.u32()
            val methodIdx = if (sizeFirst) second else first
            val size = if (sizeFirst) first else second
            if (size < 0 || size > sectionEnd - c.pos) return null
            var raw = c.readBytes(size.toInt())
            if (xor) {
                raw = ByteArray(raw.size) { (raw[it].toInt() xor XOR_KEY).toByte() }
            }
            records.add(CodeRecord(methodIdx, raw))
        }
        return records
    }

    private fun markerRatio(data: ByteArray, off: Int, sectionEnd: Int): Double? {
        if (sectionEnd - off < 2) return null
        val c = Cursor(data)
        c.seek(off)
        val methodCount = c.u16()
        var sampled = 0
        var markers = 0
        for (m in 0 until methodCount) {
            if (sectionEnd - c.pos < 8 || sampled >= 4096) break
            val size = c.u32()
            c.u32()
            if (size < 0 || size > sectionEnd - c.pos) return null
            val toSample = minOf(size.toInt(), 4096 - sampled)
            for (i in 0 until toSample) {
                if (c.u8() == XOR_KEY) markers++
            }
            sampled += toSample
            c.skip(size.toInt() - toSample)
        }
        if (sampled < 16) return null
        return markers.toDouble() / sampled
    }
}