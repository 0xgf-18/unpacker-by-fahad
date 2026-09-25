package com.dpt.unpack.checksum

import com.dpt.unpack.util.Cursor
import java.security.MessageDigest
import java.util.zip.Adler32

object DexChecksum {

    fun fix(dex: ByteArray): ByteArray {
        require(dex.size >= 112) { "dex too small" }
        var fileSize = 0L
        run {
            val c = Cursor(dex)
            c.seek(32)
            fileSize = c.u32()
        }
        require(fileSize.toInt() == dex.size) { "header file_size mismatch" }

        val out = dex.copyOf()

        val sig = MessageDigest.getInstance("SHA-1").digest(out.copyOfRange(32, fileSize.toInt()))
        System.arraycopy(sig, 0, out, 12, 20)

        val adler = Adler32()
        adler.update(out, 12, out.size - 12)
        Cursor.writeU32Le(out, 8, adler.value)

        return out
    }
}