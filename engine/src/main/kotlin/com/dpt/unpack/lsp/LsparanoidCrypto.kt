package com.dpt.unpack.lsp

/**
 * Byte-exact Kotlin port of the LSParanoid string decoder.
 *
 * Mirrors `lsparanoid-deobfuscate.py` (validated against the JVM reference:
 * seed 0x86BC12DB yields PRNG state r1=0xFFFFFFFF9FFF7887, r2=0xFFFFFFFFFFFFE878).
 */
object LsparanoidCrypto {

    private const val MASK32 = 0xFFFFFFFFL
    private const val MASK64 = -1L // 0xFFFFFFFFFFFFFFFF
    private const val CHUNK = 0x1FFF

    // 0xCB24D0A5C88C35B3 (unsigned) is > Long.MAX_VALUE; parse at class-init.
    private val PRNG_SEED2: Long = java.lang.Long.parseUnsignedLong("CB24D0A5C88C35B3", 16)

    /** Sign-normalize a 16-bit value to [-0x8000, 0x7FFF] like Java short. */
    private fun toShort(v: Long): Long {
        val t = v and 0xFFFF
        return if (t >= 0x8000) t - 0x10000 else t
    }

    private fun rotl(x: Long, k: Int): Long {
        val a = (x shl k) and MASK32
        val b = (x and MASK32) ushr (32 - k)
        return toShort(a or b)
    }

    fun prngNext(state: Long): Long {
        val s0 = toShort(state and 0xFFFF)
        val s1 = toShort((state ushr 16) and 0xFFFF)
        var nxt = toShort(s0 + s1)
        nxt = rotl(nxt, 9)
        nxt = toShort(nxt + s0)
        var s1v = toShort(s1 xor s0)
        var s0v = toShort(rotl(s0, 13))
        s0v = toShort(s0v xor s1v)
        s0v = toShort(s0v xor (s1v shl 5))
        s1v = rotl(s1v, 10)
        var result = nxt and MASK64
        result = (result shl 16) and MASK64
        result = (result or (s1v and MASK64)) and MASK64
        result = (result shl 16) and MASK64
        result = (result or (s0v and MASK64)) and MASK64
        return result
    }

    fun prngSeed(x: Long): Long {
        val z = (x xor (x ushr 33)) * 0x62A9D9ED799705F5L
        return ((z xor (z ushr 28)) * PRNG_SEED2) ushr 32
    }

    /** Truncating integer division (rounds toward zero). */
    private fun truncDiv(a: Long, b: Long): Long =
        Math.abs(a) / Math.abs(b) * (if ((a >= 0) == (b >= 0)) 1 else -1)

    private fun truncRem(a: Long, b: Long): Long {
        val q = truncDiv(a, b)
        return a - q * b
    }

    /** Decode one UTF-16 code unit. `chunk` is the full chunk vector [0, CHUNK). */
    fun getCharAt(charIndex: Long, chunks: List<List<Int>>, state: Long): Long {
        val nextState = prngNext(state)
        val ci = truncDiv(charIndex, CHUNK.toLong())
        if (ci >= chunks.size) throw IndexOutOfBoundsException("chunk $ci out of range (${chunks.size})")
        val unit = chunks[ci.toInt()][truncRem(charIndex, CHUNK.toLong()).toInt()]
        return (nextState xor ((unit.toLong() and 0xFFFF) shl 32)) and MASK64
    }

    /**
     * Returns the list of UTF-16 code units of the decoded string identified by
     * [stringId] (a 64-bit LSParanoid id as it appears in smali `const-wide`).
     */
    fun getString(stringId: Long, chunks: List<List<Int>>): List<Int> {
        var state = prngNext(prngSeed(stringId and MASK32))
        val low = (state ushr 32) and 0xFFFF
        state = prngNext(state)
        val high = (state ushr 16) and -0x10000L
        var index = ((stringId ushr 32) and MASK32) xor low xor high
        index = ((index and MASK32) xor 0x80000000L) - 0x80000000L
        var v0 = getCharAt(index, chunks, state)
        val length = (v0 ushr 32) and 0xFFFF
        val out = mutableListOf<Int>()
        for (i in 0 until length) {
            v0 = getCharAt(index + i + 1, chunks, v0)
            out.add(((v0 ushr 32) and 0xFFFF).toInt())
        }
        return out
    }

    /** Render code units as a literal smali const-string body (escaped). */
    fun unitsToSmali(units: List<Int>): String {
        val sb = StringBuilder()
        for (raw in units) {
            val v = raw and 0xFFFF
            when {
                v == 0x5C -> sb.append("\\\\")
                v == 0x22 -> sb.append("\\\"")
                v in 0x20..0x7E -> sb.append(v.toChar())
                else -> sb.append("\\u%04x".format(v))
            }
        }
        return sb.toString()
    }

    /** Short, printable preview of a chunk head for the UI (never terminal garbage). */
    fun unitsSampleForDisplay(units: List<Int>): String {
        val sb = StringBuilder()
        for (raw in units) {
            val v = raw and 0xFFFF
            sb.append(if (v == 0x20 || v in 0x21..0x7E) v.toChar().toString() else ".")
            if (sb.length >= 48) break
        }
        return sb.toString().ifEmpty { "(empty)" }
    }

    /** Parse a smali const-string body back into code units (handles \\uXXXX and simple escapes). */
    fun smaliToUnits(text: String): List<Int> {
        val out = mutableListOf<Int>()
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (c == '\\' && i + 1 < text.length) {
                val n = text[i + 1]
                if (n == 'u') {
                    out.add(text.substring(i + 2, i + 6).toInt(16))
                    i += 6
                } else if (n in "ntr\"\\") {
                    out.add(
                        when (n) {
                            'n' -> 0x0A; 't' -> 0x09; 'r' -> 0x0D; '"' -> 0x22; else -> 0x5C
                        }
                    )
                    i += 2
                } else {
                    out.add(c.code)
                    i += 1
                }
            } else {
                out.add(c.code)
                i += 1
            }
        }
        return out
    }
}