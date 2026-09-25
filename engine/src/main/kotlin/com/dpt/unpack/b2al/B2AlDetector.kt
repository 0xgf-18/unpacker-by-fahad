package com.dpt.unpack.b2al

import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Detection + recovery for B2Al-style proxy packers (encrypted DEX record
 * chain + XOR trailer).
 *
 * The carrier is a `classes*.dex` whose body is a chain of encrypted DEX
 * records plus a trailer near EOF:
 *  - the last 4 bytes are the LE record count;
 *  - each record block is [payload | 4-byte size XOR key[:4] | 64-byte key]
 *    and the payload is XOR-cycled with that key (`plain[i] ^ key[i & 63]`);
 *  - the trailer at `n - 0x48` derives first_len, key0 and the real
 *    Application class name (32 bytes XOR key0, then NUL-padded).
 *
 * The chain end is auto-detected (never assumes a fixed build offset): every
 * candidate block-end within a window before EOF is probed cheaply (decrypt the
 * first 0x2C bytes and check dex magic + header file_size + endian tag), then
 * the whole chain is walked backwards and validated; the candidate set is
 * scored (chain must end near the front stub + close to EOF).
 *
 * The classic generic detectors (DptDetector / LsparanoidDetector /
 * ArkDetector) do not recognize this scheme, so this is queried first.
 */
object B2AlDetector {

    private val DEX_MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0A)

    private const val RECORD_HDR_SIZE = 0x44 // 4 (encoded size) + 64 (key)

    data class B2AlRecord(
        val index: Int,           // 1-based
        val carrierOffset: Int,
        val size: Int,
        val sha256: String,
        val data: ByteArray,
    )

    data class B2AlInfo(
        val detected: Boolean,
        val reasons: List<String>,
        val carrierEntry: String?,
        val records: List<B2AlRecord>,
        val applicationClass: String?,
        val finalCursor: Int,
    )

    private data class Candidate(val blockEnd: Int, val finalCursor: Int, val score: Int)

    private data class Peek(val size: Int, val payloadOff: Int, val ok: Boolean)

    private class Recovery(val records: List<B2AlRecord>, val applicationClass: String?, val finalCursor: Int)

    // ---------------------------------------------------------------- utils

    private fun isDexMagic(b: ByteArray): Boolean =
        b.size >= 4 && b[0] == DEX_MAGIC[0] && b[1] == DEX_MAGIC[1] && b[2] == DEX_MAGIC[2] && b[3] == DEX_MAGIC[3]

    private fun u32(b: ByteArray, at: Int): Long =
        (b[at].toLong() and 0xFF) or ((b[at + 1].toLong() and 0xFF) shl 8) or
            ((b[at + 2].toLong() and 0xFF) shl 16) or ((b[at + 3].toLong() and 0xFF) shl 24)

    private fun isArksMarker(carrier: ByteArray, at: Int): Boolean =
        at >= 4 && carrier[at - 4] == 0x41.toByte() && carrier[at - 3] == 0x52.toByte() &&
            carrier[at - 2] == 0x4B.toByte() && carrier[at - 1] == 0x53.toByte()

    /** LE32 of `a[i] ^ k[i]` for i in 0..3 (absolute byte ranges). */
    private fun xor4(b: ByteArray, aOff: Int, kOff: Int): Int =
        (b[aOff].toInt() and 0xFF xor b[kOff].toInt() and 0xFF) or
            ((b[aOff + 1].toInt() and 0xFF xor b[kOff + 1].toInt() and 0xFF) shl 8) or
            ((b[aOff + 2].toInt() and 0xFF xor b[kOff + 2].toInt() and 0xFF) shl 16) or
            ((b[aOff + 3].toInt() and 0xFF xor b[kOff + 3].toInt() and 0xFF) shl 24)

    /** XOR `len` bytes at [off] with the 64-byte key at [keyOff], cycled by `i & 63`. */
    private fun xorBytesLen(b: ByteArray, off: Int, len: Int, keyOff: Int): ByteArray {
        val out = ByteArray(len)
        for (i in 0 until len) {
            out[i] = (b[off + i].toInt() xor (b[keyOff + (i and 0x3F)].toInt() and 0xFF)).toByte()
        }
        return out
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    // ------------------------------------------------------- chain discovery

    /**
     * Cheap structural probe of a single record whose [size][key] block ends at
     * `blockEnd`.  Verifies dex magic / header file_size / endian tag from the
     * decrypted first 0x2C bytes.
     */
    private fun peekRecord(carrier: ByteArray, blockEnd: Int): Peek {
        if (blockEnd < RECORD_HDR_SIZE || blockEnd > carrier.size) return Peek(0, 0, false)
        val keyOff = blockEnd - 0x40
        val encOff = blockEnd - 0x44
        val size = xor4(carrier, encOff, keyOff)
        val off = blockEnd - 0x44 - size
        if (size < 0x60 || off < 0 || off + 0x2C > blockEnd) return Peek(size, off, false)
        val head = xorBytesLen(carrier, off, 0x2C, keyOff)
        val ok = isDexMagic(head) &&
            u32(head, 0x20) == size.toLong() &&
            u32(head, 0x28) == 0x12345678L
        return Peek(size, off, ok)
    }

    /** Candidate block-ends for the first record (best first). Whole chain probed. */
    private fun findFirstRecordEnd(carrier: ByteArray, count: Int): List<Candidate> {
        val n = carrier.size
        val rawLo = maxOf(0x10, n - 0x300)
        val lo = rawLo + ((4 - rawLo % 4) % 4) // align to 4 so step=4 never skips a valid blockEnd
        val hi = n - 0x10
        val candidates = ArrayList<Candidate>()
        var e = lo
        while (e < hi) {
            if (!isArksMarker(carrier, e)) {
                val p = peekRecord(carrier, e)
                if (p.ok) {
                    var cur = p.payloadOff
                    var chainOk = true
                    var steps = 0
                    while (steps < count - 1) { // first peek already covered record 1
                        val p2 = peekRecord(carrier, cur)
                        if (!p2.ok) {
                            chainOk = false
                            break
                        }
                        cur = p2.payloadOff
                        steps++
                    }
                    if (chainOk && cur >= 0x40) {
                        var score = 0
                        when {
                            cur < 0x2000 -> score += 3
                            cur < 0x20000 -> score += 2
                            cur < 0x400000 -> score += 1
                        }
                        if (e > n - 0x140) score += 1 // first record tail expected near the trailer
                        candidates.add(Candidate(e, cur, score))
                    }
                }
            }
            e += 4
        }
        candidates.sortByDescending { it.score }
        return candidates
    }

    /** Full decode of one carrier's record chain. Throws when no candidate validates. */
    private fun recoverRecords(carrier: ByteArray): Recovery {
        val n = carrier.size
        if (n < 0x200) throw IllegalStateException("carrier too small")
        val count = u32(carrier, n - 4).toInt()
        if (count !in 1..20000) throw IllegalStateException("implausible record count: $count")

        var lastError: String? = null
        for (cand in findFirstRecordEnd(carrier, count)) {
            try {
                val records = ArrayList<B2AlRecord>()
                var pos = cand.blockEnd
                for (i in 0 until count) {
                    if (pos < RECORD_HDR_SIZE) throw IllegalStateException("record $i: underflow")
                    if (isArksMarker(carrier, pos)) {
                        throw IllegalStateException(
                            "ARKS variant encountered; this extractor targets the normal B2Al carrier chain"
                        )
                    }
                    val keyOff = pos - 0x40
                    val encOff = pos - 0x44
                    val size = xor4(carrier, encOff, keyOff)
                    val payloadOff = pos - 0x44 - size
                    if (size < 0x60 || payloadOff < 0 || payloadOff + size > n) {
                        throw IllegalStateException("record $i: bad offset/size")
                    }
                    val plain = xorBytesLen(carrier, payloadOff, size, keyOff)
                    if (!isDexMagic(plain)) throw IllegalStateException("record $i: bad DEX magic after full decode")
                    if (u32(plain, 0x20) != size.toLong()) throw IllegalStateException("record $i: header file_size mismatch")
                    if (u32(plain, 0x28) != 0x12345678L) throw IllegalStateException("record $i: invalid endian tag")
                    records.add(B2AlRecord(i + 1, payloadOff, size, sha256Hex(plain), plain))
                    pos = payloadOff
                }
                return Recovery(records, readTrailerApplication(carrier), pos)
            } catch (e: IllegalStateException) {
                lastError = e.message
            }
        }
        throw IllegalStateException(
            lastError?.let { "candidate chain failed full validation: $it" }
                ?: "could not locate a valid DEX record chain (unsupported variant?)"
        )
    }

    /**
     * The trailer holds the real Application class name used by the packer:
     * `first_len = LE32(C[cursor]^C[cursor+4] ...)`; `key0 = C[cursor+4:cursor+68]`;
     * the 32-byte class name is `C[cursor - first_len + j] ^ key0[j & 0x3F]`, NUL-padded.
     */
    private fun readTrailerApplication(carrier: ByteArray): String? {
        val n = carrier.size
        return try {
            val cursor = n - 0x48
            if (cursor < 0 || cursor + 68 > n) return null
            var firstLen = 0L
            for (j in 0 until 4) {
                firstLen = firstLen or
                    (((carrier[cursor + j].toInt() and 0xFF) xor (carrier[cursor + 4 + j].toInt() and 0xFF)).toLong() shl (8 * j))
            }
            if (firstLen <= 0 || firstLen > 0x400) return null
            val key0Off = cursor + 4
            val cursor2 = cursor - firstLen.toInt()
            if (cursor2 < 0 || cursor2 + 32 > n) return null
            val raw = ByteArray(32)
            for (j in 0 until 32) {
                raw[j] = (carrier[cursor2 + j].toInt() xor (carrier[key0Off + (j and 0x3F)].toInt() and 0xFF)).toByte()
            }
            var len = raw.size
            while (len > 0 && raw[len - 1] == 0.toByte()) len--
            String(raw, 0, len, Charsets.US_ASCII)
        } catch (e: Exception) {
            null
        }
    }

    // ----------------------------------------------------------- public API

    /**
     * Detects a B2Al-style carrier anywhere in the APK and recovers its records.
     * Classes*.dex entries are tried first, then any other entry with dex magic.
     */
    fun detect(apk: File): B2AlInfo {
        ZipFile(apk).use { zip ->
            val names = zip.entries().asSequence().map { it.name }.toList()
            val preferred = names.filter { it.startsWith("classes") && it.endsWith(".dex") }
            val order = preferred + names.filter { it !in preferred }
            val reasons = mutableListOf<String>()
            var tried = 0

            for (nm in order) {
                val entry = zip.getEntry(nm) ?: continue
                if (entry.isDirectory) continue
                val bytes = try {
                    zip.getInputStream(entry).use { it.readBytes() }
                } catch (e: Exception) {
                    continue
                }
                if (bytes.size < 0x200 || !isDexMagic(bytes)) continue
                tried++
                val recovery = try {
                    recoverRecords(bytes)
                } catch (e: Exception) {
                    reasons.add("candidate $nm (${bytes.size} B): ${e.message}")
                    null
                }
                if (recovery != null) {
                    reasons.add("B2Al carrier: $nm (${bytes.size} B)")
                    reasons.add("record chain: ${recovery.records.size} dexes, end @ 0x${recovery.finalCursor.toString(16)}")
                    reasons.add("application:  ${recovery.applicationClass ?: "(unknown)"}")
                    return B2AlInfo(true, reasons, nm, recovery.records, recovery.applicationClass, recovery.finalCursor)
                }
            }
            if (tried == 0) reasons.add("no dex entry big enough to be a carrier in apk")
            return B2AlInfo(false, reasons, null, emptyList(), null, 0)
        }
    }

    /**
     * Cheap probe used by the static profiler: is any of these dex carriable?
     * `buffers` are the classes*.dex raw bytes already pulled by the profiler.
     */
    fun isCarrierAmong(buffers: List<ByteArray>): Boolean =
        buffers.any { b -> b.size >= 0x200 && isDexMagic(b) && runCatching { recoverRecords(b) }.isSuccess }
}