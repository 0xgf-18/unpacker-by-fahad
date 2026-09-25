package com.dpt.unpack.elf

/**
 * Minimal ELF32/ELF64 (little-endian) symbol resolver.
 *
 * DPT-Shell stores the per-app 16-byte RC4/AES key at the data symbol
 * `DPT_UNKNOWN_DATA` (see shell/src/main/cpp/dpt.cpp). We locate that symbol
 * and return the bytes it points at.
 */
object ElfParser {

    const val DPT_UNKNOWN_DATA = "DPT_UNKNOWN_DATA"

    fun readSymbolData(so: ByteArray, symbolName: String): ByteArray? {
        if (so.size < 20) return null
        if (so[0] != 0x7f.toByte() || so[1] != 0x45.toByte() || so[2] != 0x4c.toByte() || so[3] != 0x46.toByte()) return null
        val is64 = so[4] == 2.toByte()
        val little = so[5] == 1.toByte()
        val shoff = if (is64) rdU32(so, 40, little) else rdU32(so, 32, little)
        val shentsize = if (is64) rdU16(so, 58, little) else rdU16(so, 46, little)
        val shnum = if (is64) rdU16(so, 60, little) else rdU16(so, 48, little)
        val shstrndx = if (is64) rdU16(so, 62, little) else rdU16(so, 50, little)
        if (shentsize < 32 || shnum == 0 || shoff == 0L) return null

        class Sec(val nameOff: Int, val type: Int, val offset: Long, val size: Long, val addr: Long, val link: Int, val entsize: Long) {
            var name: String? = null
        }

        fun sec(i: Int): Sec {
            val o = shoff + i.toLong() * shentsize
            return if (is64) Sec(
                rdU32(so, o, little).toInt(), rdU32(so, o + 4, little).toInt(),
                rdU64(so, o + 24, little), rdU64(so, o + 32, little), rdU64(so, o + 16, little),
                rdU32(so, o + 40, little).toInt(), rdU64(so, o + 56, little)
            ) else {
                // ELF32 Shdr: sh_name@0 sh_type@4 sh_flags@8 sh_addr@12 sh_offset@16 sh_size@20 sh_link@24 sh_info@28 sh_addralign@32 sh_entsize@36
                Sec(
                    rdU32(so, o, little).toInt(), rdU32(so, o + 4, little).toInt(),
                    rdU32(so, o + 16, little), rdU32(so, o + 20, little), rdU32(so, o + 12, little),
                    rdU32(so, o + 24, little).toInt(), rdU32(so, o + 36, little)
                )
            }
        }

        val sections = ArrayList<Sec>(shnum)
        for (i in 0 until shnum) sections.add(sec(i))
        val strTabSec = if (shstrndx in 0 until shnum) sections[shstrndx] else null
        fun secName(s: Sec): String? {
            s.name?.let { return it }
            if (strTabSec == null || strTabSec.size <= 0) return null
            s.name = readCString(so, strTabSec.offset + s.nameOff)
            return s.name
        }

        for (symTab in sections) {
            if (symTab.type != 2 && symTab.type != 11) continue // SHT_SYMTAB / SHT_DYNSYM
            val strings = sections.getOrNull(symTab.link) ?: continue
            if (strings.size <= 0 || symTab.size <= 0) continue
            val symEnt = if (is64) 24 else 16
            val entrySize = if (symTab.entsize >= symEnt) symTab.entsize.toInt() else symEnt
            val count = (symTab.size / entrySize).toInt()
            for (i in 0 until count) {
                val o = symTab.offset + i.toLong() * entrySize
                val nameOff = rdU32(so, o, little).toInt()
                val stValue = if (is64) rdU64(so, o + 8, little) else rdU32(so, o + 4, little)
                val stSize = if (is64) rdU64(so, o + 16, little) else rdU32(so, o + 8, little)
                val stShndx = if (is64) rdU16(so, o + 6, little) else rdU16(so, o + 14, little)
                val nm = readCString(so, strings.offset + nameOff) ?: continue
                if (nm != symbolName) continue
                if (stSize <= 0) return null
                val target = sections.getOrNull(stShndx.toInt()) ?: return null
                val dataOff = target.offset + (stValue - target.addr)
                if (dataOff < 0 || dataOff + stSize > so.size) return null
                return so.copyOfRange(dataOff.toInt(), (dataOff + stSize).toInt())
            }
        }
        return null
    }

    private fun readCString(b: ByteArray, off: Long): String? {
        if (off < 0 || off >= b.size) return null
        val sb = StringBuilder()
        var i = off
        while (i < b.size) {
            val c = b[i.toInt()].toInt() and 0xFF
            if (c == 0) return sb.toString()
            sb.append(c.toChar())
            i++
        }
        return sb.toString()
    }

    private fun rdU16(b: ByteArray, off: Long, le: Boolean): Int {
        val o = off.toInt()
        val v0 = b[o].toInt() and 0xFF
        val v1 = b[o + 1].toInt() and 0xFF
        return if (le) v0 or (v1 shl 8) else (v0 shl 8) or v1
    }

    private fun rdU32(b: ByteArray, off: Long, le: Boolean): Long {
        val o = off.toInt()
        var v = 0L
        for (k in 0 until 4) {
            val idx = if (le) o + k else o + (3 - k)
            v = v or ((b[idx].toLong() and 0xFF) shl (8 * k))
        }
        return v
    }

    private fun rdU64(b: ByteArray, off: Long, le: Boolean): Long {
        val o = off.toInt()
        var v = 0L
        for (k in 0 until 8) {
            val idx = if (le) o + k else o + (7 - k)
            v = v or ((b[idx].toLong() and 0xFF) shl (8 * k))
        }
        return v
    }
}