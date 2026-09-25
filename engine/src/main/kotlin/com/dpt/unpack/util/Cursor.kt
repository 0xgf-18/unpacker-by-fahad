package com.dpt.unpack.util

class Cursor(val data: ByteArray, var pos: Int = 0) {

    fun u8(): Int = data[pos++].toInt() and 0xFF

    fun u16(): Int = u8() or (u8() shl 8)

    fun u32(): Long =
        u8().toLong() or (u8().toLong() shl 8) or (u8().toLong() shl 16) or (u8().toLong() shl 24)

    fun uleb128(): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = u8()
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
    }

    fun readBytes(n: Int): ByteArray {
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun skip(n: Int) {
        pos += n
    }

    fun remaining(): Int = data.size - pos

    fun seek(p: Int) {
        pos = p
    }

    companion object {
        fun writeU32Le(out: ByteArray, at: Int, value: Long) {
            out[at] = (value and 0xFF).toByte()
            out[at + 1] = ((value shr 8) and 0xFF).toByte()
            out[at + 2] = ((value shr 16) and 0xFF).toByte()
            out[at + 3] = ((value shr 24) and 0xFF).toByte()
        }

        fun readU32Le(data: ByteArray, at: Int): Long =
            (data[at].toLong() and 0xFF) or
                ((data[at + 1].toLong() and 0xFF) shl 8) or
                ((data[at + 2].toLong() and 0xFF) shl 16) or
                ((data[at + 3].toLong() and 0xFF) shl 24)
    }
}