package com.dpt.unpack.validate

import com.dpt.unpack.util.Cursor
import java.security.MessageDigest
import java.util.zip.Adler32

object DexValidator {

    private val DEX_MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0A)

    fun isDex(b: ByteArray): Boolean =
        b.size >= 8 && DEX_MAGIC.indices.all { DEX_MAGIC[it] == b[it] }

    fun validate(dex: ByteArray): List<String> {
        val problems = mutableListOf<String>()
        if (!isDex(dex)) {
            problems.add("not a dex file (magic mismatch)")
            return problems
        }
        if (dex.size < 112) {
            problems.add("truncated header")
            return problems
        }

        val fileSize = Cursor.readU32Le(dex, 32)
        if (fileSize.toInt() != dex.size) {
            problems.add("header file_size=${fileSize} != actual=${dex.size}")
        }

        val sig = MessageDigest.getInstance("SHA-1").digest(dex.copyOfRange(32, dex.size))
        val storedSig = dex.copyOfRange(12, 32)
        if (!sig.contentEquals(storedSig)) {
            problems.add("SHA-1 signature mismatch (not re-hashed?)")
        }

        val adler = Adler32()
        adler.update(dex, 12, dex.size - 12)
        if (Cursor.readU32Le(dex, 8) != adler.value) {
            problems.add("Adler-32 checksum mismatch")
        }

        return problems
    }
}