package com.dpt.unpack.dex

import com.dpt.unpack.checksum.DexChecksum

/**
 * Builds a minimal standalone dex containing a no-op JniBridge class whose
 * public static `clinit()V` method satisfies the packer's static-initializer
 * hooks (Class.forName + getDeclaredMethod("clinit") + invoke).
 *
 * The class descriptor is passed in because DPT variants each use their own
 * shell package (e.g. `com.faraz.playz.shell.JniBridge` or
 * `PVzrIYSsiUwERDAL.JniBridge`); when the restore drops the packed stub dex the
 * app's direct type reference to JniBridge would otherwise throw
 * NoClassDefFoundError at class-load time.  The real JniBridge starts the shell
 * runtime; a no-op preserves the hooks' contract (they must not throw) while
 * leaving the unpacked app fully inert.
 */
object DummyJniBridge {

    fun build(desc: String = "Lcom/faraz/playz/shell/JniBridge;", name: String = "clinit"): ByteArray {
        val ret = "V"
        val objDesc = "Ljava/lang/Object;"

        val dataStart = 0xC4
        fun strSize(s: String) = 1 + s.length + 1                       // len uleb (ascii) + bytes + 0
        fun alignFour(x: Int) = (x + 3) / 4 * 4

        val s0 = dataStart
        val s1 = s0 + strSize(desc)
        val s2 = s1 + strSize(name)
        val s3 = s2 + strSize(ret)
        val afterStrings = s3 + strSize(objDesc)
        val codeOff = alignFour(afterStrings)
        val codeSize = 20                                                // 16 + insns(2) + pad(2)
        val classDataOff = alignFour(codeOff + codeSize)
        val classDataSize = 8
        val mapOff = alignFour(classDataOff + classDataSize)
        val mapEntries = 10
        val fileSize = mapOff + 4 + mapEntries * 12

        val dex = ByteArray(fileSize)
        val u16 = { at: Int, v: Int ->
            dex[at] = (v and 0xFF).toByte(); dex[at + 1] = ((v shr 8) and 0xFF).toByte()
        }
        val u32 = { at: Int, v: Long ->
            dex[at] = (v and 0xFF).toByte(); dex[at + 1] = ((v shr 8) and 0xFF).toByte()
            dex[at + 2] = ((v shr 16) and 0xFF).toByte(); dex[at + 3] = ((v shr 24) and 0xFF).toByte()
        }

// ---- header ----
        System.arraycopy(byteArrayOf(0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00), 0, dex, 0, 8)
        u32(32, fileSize.toLong())
        u32(36, 0x70)
        u32(40, 0x12345678L)
        u32(44, 0); u32(48, 0)                       // link
        u32(52, mapOff.toLong())
        u32(56, 4); u32(60, 0x70)                    // string_ids
        u32(64, 3); u32(68, 0x80)                    // type_ids
        u32(72, 1); u32(76, 0x8C)                    // proto_ids
        u32(80, 0); u32(84, 0)                       // field_ids
        u32(88, 1); u32(92, 0x98)                    // method_ids
        u32(96, 1); u32(100, 0xA4)                   // class_defs
        u32(104, (fileSize - dataStart).toLong()); u32(108, dataStart.toLong())

        // ---- string_ids ----
        u32(0x70, s0.toLong()); u32(0x74, s1.toLong())
        u32(0x78, s2.toLong()); u32(0x7C, s3.toLong())

        // ---- type_ids: [0]=JniBridge, [1]=V, [2]=Object ----
        u32(0x80, 0); u32(0x84, 2); u32(0x88, 3)

        // ---- proto_ids: clinit ()V ----
        u32(0x8C, 2); u32(0x90, 1); u32(0x94, 0)        // shorty=V, return=V, params=0

        // ---- method_ids: JniBridge.clinit ()V ---- (8 bytes: ushort class_idx, ushort proto_idx, uint name_idx)
        u16(0x98, 0); u16(0x9A, 0); u32(0x9C, 1)

        // ---- class_defs: public JniBridge extends Object ----
        u32(0xA4, 0)                                   // class_idx
        u32(0xA8, 0x01)                                // ACC_PUBLIC
        u32(0xAC, 2)                                   // superclass = Object
        u32(0xB0, 0)                                   // interfaces_off
        u32(0xB4, 0xFFFFFFFFL)                         // source_file = NO_INDEX
        u32(0xB8, 0)                                   // annotations_off
        u32(0xBC, classDataOff.toLong())
        u32(0xC0, 0)                                   // static_values_off

        // ---- string_data ----
        writeStringData(dex, s0, desc)
        writeStringData(dex, s1, name)
        writeStringData(dex, s2, ret)
        writeStringData(dex, s3, objDesc)

        // ---- code_item: { return-void } ----
        u16(codeOff, 0); u16(codeOff + 2, 0); u16(codeOff + 4, 0); u16(codeOff + 6, 0)
        u32(codeOff + 8, 0)                            // debug_info_off
        u32(codeOff + 12, 1)                           // insns_size = 1
        u16(codeOff + 16, 0x000E)                      // return-void
        u16(codeOff + 18, 0)                           // padding

        // ---- class_data: 0 fields, 1 direct method ----
        dex[classDataOff] = 0x00.toByte()              // static_fields = 0
        dex[classDataOff + 1] = 0x00.toByte()          // instance_fields = 0
        dex[classDataOff + 2] = 0x01.toByte()          // direct_methods = 1
        dex[classDataOff + 3] = 0x00.toByte()          // virtual_methods = 0
        dex[classDataOff + 4] = 0x00.toByte()          // method_idx_diff = 0
        dex[classDataOff + 5] = 0x09.toByte()          // access = PUBLIC|STATIC
        writeUleb128(dex, classDataOff + 6, codeOff)   // code_off

        // ---- map_list ----
        mapList(
            dex, mapOff,
            intArrayOf(0x0000, 0x0001, 0x0002, 0x0003, 0x0005, 0x0006, 0x2002, 0x2001, 0x2000, 0x1000),
            intArrayOf(1, 4, 3, 1, 1, 1, 4, 1, 1, 1),
            intArrayOf(0x000, 0x070, 0x080, 0x08C, 0x098, 0x0A4, s0, codeOff, classDataOff, mapOff),
        )

        return DexChecksum.fix(dex)
    }

    /**
     * Scans the restored payload dexes for a *referenced-but-not-defined*
     * `...JniBridge` type (the app kept a direct type reference to the shell
     * class, but the restore drops the packed stub dex that defined it).
     *
     * @return (typeDescriptor, referencedMethodName) of the first offending
     *         bridge, or null when every bridge type is already defined.
     */
    fun detectBridge(payloadDexes: List<ByteArray>): Pair<String, String>? {
        data class BridgeHit(val typeIdx: Int, val desc: String, val methodName: String?)

        val bridges = mutableListOf<BridgeHit>()
        val definedTypes = mutableSetOf<Pair<Int, String>>()   // (dexIdx, desc)

        fun u16(d: ByteArray, off: Int) =
            ((d.getOrElse(off) { 0 }.toInt() and 0xFF) or
                ((d.getOrElse(off + 1) { 0 }.toInt() and 0xFF) shl 8))

        fun u32(d: ByteArray, off: Int) =
            (d.getOrElse(off) { 0 }.toLong() and 0xFF) or
                ((d.getOrElse(off + 1) { 0 }.toLong() and 0xFF) shl 8) or
                ((d.getOrElse(off + 2) { 0 }.toLong() and 0xFF) shl 16) or
                ((d.getOrElse(off + 3) { 0 }.toLong() and 0xFF) shl 24)

        fun mutf8String(d: ByteArray, stringIdx: Int, stringIdsOff: Int, stringIdsSize: Int): String? {
            if (stringIdx < 0 || stringIdx >= stringIdsSize) return null
            val dataOff = u32(d, stringIdsOff + stringIdx * 4)
            if (dataOff >= d.size) return null
            // string_data_item: uleb128 utf16_size then UTF-8 bytes then NUL
            var p = dataOff.toInt()
            var v = d[p++].toInt() and 0xFF
            while (v and 0x80 != 0) { v = (d[p++].toInt() and 0xFF) }
            val sb = StringBuilder()
            while (p < d.size) {
                val b = d[p++].toInt()
                if (b == 0) break
                sb.append(b.toChar())
            }
            return sb.toString()
        }

        for ((dexIdx, dex) in payloadDexes.withIndex()) {
            if (dex.size < 0x70) continue
            val stringIdsSize = u32(dex, 0x38).toInt()
            val stringIdsOff = u32(dex, 0x3C).toInt()
            val typeIdsSize = u32(dex, 0x40).toInt()
            val typeIdsOff = u32(dex, 0x44).toInt()
            val methodIdsSize = u32(dex, 0x58).toInt()
            val methodIdsOff = u32(dex, 0x5C).toInt()
            val classDefsSize = u32(dex, 0x60).toInt()
            val classDefsOff = u32(dex, 0x64).toInt()

            // collect all type descriptors mentioning JniBridge
            val bridgeTypeIdx = mutableMapOf<Int, String>()
            for (t in 0 until typeIdsSize) {
                val sIdx = u32(dex, typeIdsOff + t * 4).toInt()
                val desc = sIdx.let { mutf8String(dex, it, stringIdsOff, stringIdsSize) }
                if (desc != null && desc.contains("JniBridge")) bridgeTypeIdx[t] = desc
            }
            if (bridgeTypeIdx.isEmpty()) continue

            // confirm which bridge types are actually referenced from this dex
            val referenced = hashSetOf<Int>()
            for (m in 0 until methodIdsSize) {
                val clsIdx = u16(dex, methodIdsOff + m * 8)
                if (clsIdx in bridgeTypeIdx) {
                    val nameIdx = u32(dex, methodIdsOff + m * 8 + 4)
                    val name = mutf8String(dex, nameIdx.toInt(), stringIdsOff, stringIdsSize)
                    bridges.add(BridgeHit(clsIdx, bridgeTypeIdx[clsIdx]!!, name))
                }
            }

            // record which bridge types this dex defines
            for (c in 0 until classDefsSize) {
                val clsIdx = u32(dex, classDefsOff + c * 32).toInt()
                if (clsIdx in bridgeTypeIdx) definedTypes.add(dexIdx to bridgeTypeIdx[clsIdx]!!)
            }
        }

        // a bridge type is "missing" when no payload dex defines it
        val definedDescs = definedTypes.map { it.second }.toSet()
        return bridges.firstOrNull { it.desc !in definedDescs }?.let { it.desc to (it.methodName ?: "clinit") }
    }

    private fun writeStringData(dex: ByteArray, at: Int, s: String) {
        val raw = s.toByteArray(Charsets.UTF_8)
        dex[at] = (raw.size and 0x7F).toByte()
        System.arraycopy(raw, 0, dex, at + 1, raw.size)
        dex[at + 1 + raw.size] = 0x00.toByte()
    }

    private fun writeUleb128(dex: ByteArray, at: Int, v: Int) {
        var value = v
        var p = at
        do {
            var b = value and 0x7F
            value = value ushr 7
            if (value != 0) b = b or 0x80
            dex[p++] = b.toByte()
        } while (value != 0)
    }

    private fun mapList(dex: ByteArray, at: Int, types: IntArray, sizes: IntArray, offsets: IntArray) {
        var p = at
        dex[p++] = types.size.toByte(); dex[p++] = 0; dex[p++] = 0; dex[p++] = 0
        for (i in types.indices) {
            dex[p++] = (types[i] and 0xFF).toByte(); dex[p++] = ((types[i] shr 8) and 0xFF).toByte()
            dex[p++] = 0; dex[p++] = 0
            dex[p++] = (sizes[i] and 0xFF).toByte(); dex[p++] = ((sizes[i] shr 8) and 0xFF).toByte()
            dex[p++] = ((sizes[i] shr 16) and 0xFF).toByte(); dex[p++] = ((sizes[i] shr 24) and 0xFF).toByte()
            dex[p++] = (offsets[i] and 0xFF).toByte(); dex[p++] = ((offsets[i] shr 8) and 0xFF).toByte()
            dex[p++] = ((offsets[i] shr 16) and 0xFF).toByte(); dex[p++] = ((offsets[i] shr 24) and 0xFF).toByte()
        }
    }
}