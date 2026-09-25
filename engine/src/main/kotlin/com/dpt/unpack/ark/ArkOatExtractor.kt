package com.dpt.unpack.ark

import com.dpt.unpack.util.Cursor

/**
 * Extracts the real dex payload out of the OAT ELF containers that 360 Jiagu
 * writes into /data/data/<pkg>/code_cache/ark_opt/ (named ark_payload_*.dex,
 * but each is an ELF/OAT "oat\n088" file with the dex embedded).
 *
 * On BlueStacks the embedded dex sits at a fixed offset; a generic scan is used
 * so other devices/versions (plain dex dumps, different containers) also work.
 */
object ArkOatExtractor {

    private val DEX_MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0A)
    private val VERSIONS = setOf("035\u0000", "036\u0000", "037\u0000", "038\u0000", "039\u0000", "040\u0000")

    /** Returns the embedded dex bytes, or the file itself when it already is a dex. */
    fun extract(container: ByteArray, sourceName: String): ByteArray {
        if (container.size >= 8 && DEX_MAGIC.indices.all { DEX_MAGIC[it] == container[it] }) {
            return container // already a plain dex dump
        }
        for (off in 0 until container.size - 40) {
            if (!DEX_MAGIC.indices.all { DEX_MAGIC[it] == container[off + it] }) continue
            val version = String(container, off + 4, 4, Charsets.ISO_8859_1)
            if (VERSIONS.none { version == it }) continue
            val fileSize = Cursor.readU32Le(container, off + 32).toInt()
            val headerSize = Cursor.readU32Le(container, off + 36).toInt()
            val endian = Cursor.readU32Le(container, off + 40)
            if (headerSize != 0x70) continue
            if (endian != 0x12345678L) continue
            if (fileSize < headerSize || off + fileSize > container.size) continue
            val dex = container.copyOfRange(off, off + fileSize)
            if (!DEX_MAGIC.indices.all { DEX_MAGIC[it] == dex[it] }) continue
            return dex
        }
        throw IllegalStateException("no embedded dex found in $sourceName (${container.size} bytes)")
    }
}