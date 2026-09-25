package com.dpt.unpack.axml

/**
 * Minimal binary AndroidManifest.xml string-pool extractor.
 * Returns every string stored in the RES_STRING_POOL (type 0x0001) chunk.
 */
object AxmlStrings {

    fun extract(axml: ByteArray): List<String> {
        val result = ArrayList<String>()
        if (axml.size < 8) return result
        var off = 8
        while (off + 8 <= axml.size) {
            val type = u16(axml, off) and 0xFFFF
            val headerSize = u16(axml, off + 2) and 0xFFFF
            val chunkSize = u32(axml, off + 4)
            if (chunkSize < 8 || off + chunkSize > axml.size) break
            if (type == 0x0001) {
                val stringCount = u32(axml, off + 8)
                val flags = u32(axml, off + 16)
                val stringsStart = u32(axml, off + 20)
                val utf8 = (flags and 0x100) != 0
                var p = off + headerSize
                for (i in 0 until stringCount) {
                    val strOff = u32(axml, p + i * 4)
                    result.add(
                        if (utf8) readUtf8(axml, off + stringsStart + strOff)
                        else readUtf16(axml, off + stringsStart + strOff)
                    )
                }
                return result
            }
            off += chunkSize
        }
        return result
    }

    private fun readUtf8(b: ByteArray, start: Int): String {
        var i = start
        if (i >= b.size) return ""
        val charLen = readLen8(b, i).also { i = it.second }
        val byteLen = readLen8(b, i).also { i = it.second }
        if (byteLen.first < 0 || i + byteLen.first > b.size) return ""
        if (charLen.first < 0 || byteLen.first < 0) return ""
        return String(b, i, byteLen.first, Charsets.UTF_8)
    }

    private fun readUtf16(b: ByteArray, start: Int): String {
        var i = start
        if (i + 2 > b.size) return ""
        val charLen = readLen16(b, i).also { i = it.second }
        val sb = StringBuilder(charLen.first)
        for (k in 0 until charLen.first) {
            if (i + 2 > b.size) break
            sb.append(u16(b, i).toChar())
            i += 2
        }
        return sb.toString()
    }

    private fun readLen8(b: ByteArray, pos: Int): Pair<Int, Int> {
        val v = b[pos].toInt() and 0xFF
        if (v and 0x80 == 0) return v to pos + 1
        if (pos + 2 > b.size) return 0 to pos + 1
        val v2 = ((v and 0x7f) shl 8) or (b[pos + 1].toInt() and 0xFF)
        return v2 to pos + 2
    }

    private fun readLen16(b: ByteArray, pos: Int): Pair<Int, Int> {
        val v = u16(b, pos)
        if (v and 0x8000 == 0) return v to pos + 2
        if (pos + 4 > b.size) return 0 to pos + 2
        val v2 = ((v and 0x7fff) shl 16) or u16(b, pos + 2)
        return v2 to pos + 4
    }

    private fun u16(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

    private fun u32(b: ByteArray, o: Int): Int {
        var v = 0
        for (k in 0 until 4) v = v or ((b[o + k].toInt() and 0xFF) shl (8 * k))
        return v
    }
}