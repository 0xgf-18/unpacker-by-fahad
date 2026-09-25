package com.dpt.unpack.detection

import com.dpt.unpack.util.Cursor
import java.io.File
import java.util.zip.ZipFile

data class PayloadDex(val name: String, val bytes: ByteArray)

data class DetectionResult(
    val detected: Boolean,
    val reasons: List<String>,
    val payloadDexes: List<PayloadDex>,
    val codeAsset: ByteArray?,
    val assetNames: List<String>,
)

object DptDetector {
    const val CODE_ASSET = "assets/OoooooOooo"
    const val CONFIG_ASSET = "assets/d_shell_data_001"

    private val DEX_MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0A)

    fun detect(apk: File): DetectionResult {
        ZipFile(apk).use { zip ->
            val assetNames = zip.entries().asSequence().map { it.name }.toList()
            val reasons = mutableListOf<String>()

            val shellEntry = zip.getEntry("classes.dex")
            if (shellEntry == null) {
                return DetectionResult(false, listOf("no classes.dex in apk"), emptyList(), null, assetNames)
            }

            val shellDex = zip.getInputStream(shellEntry).readAllBytes()
            if (!isDexMagic(shellDex)) {
                return DetectionResult(
                    false,
                    listOf("classes.dex has no dex magic"),
                    emptyList(),
                    null,
                    assetNames,
                )
            }
            reasons.add("shell classes.dex = ${shellDex.size} bytes (dex magic ok)")

            val codeAsset = zip.getEntry(CODE_ASSET)?.let { zip.getInputStream(it).readAllBytes() }
            reasons.add(
                if (codeAsset != null) "$CODE_ASSET present (${codeAsset.size} bytes)" else "$CODE_ASSET missing"
            )

            val payloadDexes = scanPayloadDexes(shellDex)
            if (payloadDexes.isEmpty()) {
                reasons.add("no embedded payload dex found inside classes.dex")
            } else {
                reasons.add("embedded payload dexes: ${payloadDexes.joinToString { "${it.name} (${it.bytes.size})" }}")
            }

            if (assetNames.contains(CONFIG_ASSET)) reasons.add("$CONFIG_ASSET present (shell config)")
            if (assetNames.any { it.startsWith("lib/") && it.endsWith(".so") }) reasons.add("native libs present")
            reasons.add("apk entries: ${assetNames.size} total")

            val detected = payloadDexes.isNotEmpty() && codeAsset != null
            return DetectionResult(detected, reasons, payloadDexes, codeAsset, assetNames)
        }
    }

    private fun isDexMagic(b: ByteArray): Boolean =
        b.size >= 4 && b[0] == DEX_MAGIC[0] && b[1] == DEX_MAGIC[1] && b[2] == DEX_MAGIC[2] && b[3] == DEX_MAGIC[3]

    private fun scanPayloadDexes(shellDex: ByteArray): List<PayloadDex> {
        // Layout type 1 (v1.12.2+ present scheme): the payload dexes are stored inside
        // an embedded ZIP appended to the shell proxy dex, followed by a 4-byte LE
        // length whose bytes are byte-swapped (BSWAP) on the native side. Prefer this
        // when a PK\x03\x04 local header sits inside the shell dex.
        tryZipEmbedded(shellDex)?.let { return it }

        val candidates = ArrayList<Pair<Int, Long>>()
        for (off in 8 until shellDex.size - 40) {
            if (shellDex[off] != DEX_MAGIC[0] || shellDex[off + 1] != DEX_MAGIC[1] ||
                shellDex[off + 2] != DEX_MAGIC[2] || shellDex[off + 3] != DEX_MAGIC[3]
            ) continue
            if (shellDex[off + 4] != 0x30.toByte() || shellDex[off + 5] != 0x33.toByte() ||
                shellDex[off + 6] != 0x35.toByte() || shellDex[off + 7] != 0x00.toByte()
            ) continue
            val fileSize = Cursor.readU32Le(shellDex, off + 32)
            if (fileSize < 112 || off + fileSize > shellDex.size) continue
            candidates.add(off to fileSize)
        }
        if (candidates.isEmpty()) return emptyList()

        val offsets = candidates.map { it.first }
        val offsetSet = offsets.toHashSet()
        val nextOf = HashMap<Int, Int>()
        val indegree = HashMap<Int, Int>()
        // A decoy: a fake zip local file header placed right before the next payload dex.
        val hasDecoy = { expected: Int -> expected + 2 < shellDex.size &&
            shellDex[expected] == 0x50.toByte() && shellDex[expected + 1] == 0x4B.toByte() &&
            shellDex[expected + 2] == 0x03.toByte() && shellDex[expected + 3] == 0x04.toByte()
        }
        val nextOfCandidate = { off: Int, size: Long ->
            var n = off + size.toInt()
            if (offsetSet.contains(n)) {
                n
            } else if (hasDecoy(n)) {
                val nlen = Cursor.readU32Le(shellDex, n + 26).toInt() and 0xFFFF
                val elen = Cursor.readU32Le(shellDex, n + 28).toInt() and 0xFFFF
                val candidate = n + 30 + nlen + elen
                if (offsetSet.contains(candidate)) candidate else null
            } else {
                null
            }
        }
        for ((off, size) in candidates) {
            val n = nextOfCandidate(off, size)
            if (n != null) {
                nextOf[off] = n
                indegree[n] = (indegree[n] ?: 0) + 1
            }
        }

        val heads = candidates.filter { (off, _) -> indegree.getOrDefault(off, 0) == 0 }.map { it.first }.sorted()
        val chainLengths = HashMap<Int, Int>()
        for (h in heads) {
            var len = 0
            var cur = h
            while (true) {
                len++
                val n = nextOf[cur] ?: break
                cur = n
            }
            chainLengths[h] = len
        }
        val bestHead = when {
            chainLengths.isEmpty() -> candidates.minBy { it.first }?.first ?: return emptyList()
            else -> chainLengths.maxBy { it.value }!!.key
        }

        val chain = ArrayList<Int>()
        var cur = bestHead
        while (true) {
            chain.add(cur)
            cur = nextOf[cur] ?: break
        }

        return chain.mapIndexed { i, off ->
            val size = candidates.first { it.first == off }.second.toInt()
            PayloadDex(if (i == 0) "classes.dex" else "classes${i + 1}.dex", shellDex.copyOfRange(off, off + size))
        }
    }

    /**
     * Attempts to recover payload dexes from an embedded ZIP appended to the shell
     * proxy dex (v1.12.2+ "combineDexZipWithShellDex" scheme). The ZIP local-header
     * starts at the first PK\x03\x04. Uses ZipInputStream to stream local headers
     * sequentially, which tolerates the falsified/decoys in the central directory
     * that the packer injects (matches ZipArchive's parse of the whole blob).
     */
    private fun tryZipEmbedded(shellDex: ByteArray): List<PayloadDex>? {
        val pk = findPk3(shellDex)
        if (pk == null) return null
        val zipBlob = shellDex.copyOfRange(pk, shellDex.size)
        if (zipBlob.size < 22) return null

        // The trailer (4 bytes) holds the ZIP length with the BSWAP quirk; we don't
        // strictly need it since ZipInputStream stops at the actual end of entries.
        val entries = ArrayList<Pair<String, ByteArray>>()
        try {
            java.util.zip.ZipInputStream(java.io.ByteArrayInputStream(zipBlob)).use { zin ->
                var entry = zin.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory) {
                        val data = zin.readAllBytes()
                        entries.add(entry.name to data)
                    }
                    zin.closeEntry()
                    entry = zin.nextEntry
                }
            }
        } catch (e: Exception) {
            return null
        }
        if (entries.isEmpty()) return null
        val dexes = entries
            .filter { (name, _) -> name.contains("classes") && name.endsWith(".dex") }
            .sortedBy { (name, _) ->
                when {
                    name == "classes.dex" -> 0
                    else -> name.removePrefix("classes").removeSuffix(".dex").toIntOrNull() ?: Int.MAX_VALUE
                }
            }
            .map { (name, bytes) -> PayloadDex(name, bytes) }
        return dexes.ifEmpty { null }
    }

    private fun findPk3(b: ByteArray): Int? {
        for (i in 0 until b.size - 4) {
            if (b[i] == 0x50.toByte() && b[i + 1] == 0x4B.toByte() &&
                b[i + 2] == 0x03.toByte() && b[i + 3] == 0x04.toByte()
            ) return i
        }
        return null
    }
}