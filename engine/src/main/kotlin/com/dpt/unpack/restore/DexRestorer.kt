package com.dpt.unpack.restore

import com.dpt.unpack.checksum.DexChecksum
import com.dpt.unpack.code.CodeRecord
import com.dpt.unpack.crypto.DptCrypto
import com.dpt.unpack.dex.DexParser

data class RestoreResult(
    val dex: ByteArray,
    val patched: Int,
    val totalRecords: Int,
    val skipped: Int,
    val mismatches: Int,
    val hooksNeutralized: Int = 0,
    val bridgesNeutralized: Int = 0,
)

object DexRestorer {

    /**
     * @param aesKey when set, each stored insns blob is RC4-decrypted first using
     *               key = aesKey || LE(methodIdx) (current DPT-Shell crypto scheme).
     */
    fun restore(dex: ByteArray, records: List<CodeRecord>, aesKey: ByteArray? = null, stripHooks: Boolean = true, label: String = ""): RestoreResult {
        val methods = DexParser.parseMethods(dex)
        val byIdx = methods.associateBy { it.methodIdx }
        val out = dex.copyOf()

        var patched = 0
        var skipped = 0
        var mismatches = 0

        for (rec in records) {
            val m = byIdx[rec.methodIdx]
            if (m == null) {
                skipped++
                continue
            }
            val writeData = if (aesKey != null) {
                val idx = (rec.methodIdx and 0xFFFFFFFFL).toInt()
                DptCrypto.rc4(DptCrypto.buildInsnsRc4Key(aesKey, idx), rec.insns)
            } else {
                rec.insns
            }
            val capacity = m.insnsByteSize
            if (writeData.size != capacity) mismatches++

            val writeLen = minOf(writeData.size, capacity)
            if (writeLen > 0) {
                System.arraycopy(writeData, 0, out, m.codeOff.toInt() + 16, writeLen)
                patched++
            }
            for (i in writeLen until capacity) {
                out[m.codeOff.toInt() + 16 + i] = 0
            }
        }

        val hooks = if (stripHooks) DptHookStripper.strip(out) else 0
        val bridges = if (stripHooks) DptHookStripper.stripBridgeCalls(out, label) else 0
        if (out.size > 50000) {
            val sb = StringBuilder()
            for (i in 0 until 32) { sb.append(java.lang.String.format("%02X", out[40268 + i].toInt() and 0xFF)); if (i % 2 == 1) sb.append(' ') }
            println("   RESTORER[$label] RETURN out@40268: $sb")
        }
        return RestoreResult(DexChecksum.fix(out), patched, records.size, skipped, mismatches, hooks, bridges)
    }
}