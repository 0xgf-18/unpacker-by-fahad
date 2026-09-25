package com.dpt.unpack.restore

import com.dpt.unpack.dex.DexParser

/**
 * Neutralizes the DPT-Shell bootstrap hooks injected into every packed class.
 *
 * The packer appends to each app class a `static synthetic <randomName>()V`
 * method whose body XOR-decodes `com.faraz.playz.shell.JniBridge` / `clinit`
 * and reflects `Class.forName(...).getDeclaredMethod("clinit").invoke(null)`.
 * The class `<clinit>` was rewritten to call that helper. The referenced shell
 * class only exists at runtime (it is injected by the native loader), so on a
 * statically unpacked dex that `Class.forName` throws {@code ClassNotFoundException}
 * and the app crashes at startup.
 *
 * Detection is deliberately independent of the dex string/proto tables (which a
 * repacked dex may not even expose coherently). Instead the signature used is
 * purely structural and was validated against ground-truth unpack output:
 *
 *   - method flags are STATIC|SYNTHETIC (0x8|0x1000),
 *   - it is invoked with an empty register list from another method of the same
 *     class (dalvik 35c `invoke-static {}`  -> bytes `71 00 <midx16>`),
 *   - its body is EXACTLY the uniform hook fingerprint: 75 code units (150 bytes).
 *     A mere ">= 16 units" threshold is not enough: legit enum synthetics such
 *     as `$values()` are static+synthetic, are invoked with `{}` from `values()`,
 *     and have non-trivial bodies. Neutralizing one produces `return-void` where
 *     an array return is expected -> ART `VerifyError` at startup (observed on
 *     androidx.lifecycle.Lifecycle$State). All 780 real hooks measure exactly
 *     75 units; compiler `$values()` helpers are smaller (<= ~30 units).
 *
 * Fix: rewrite the hook body in place to `return-void` + nops, keeping code
 * items and class_data layout untouched (still fully valid dex, no size/offset
 * churn, the no-op methods keep resolving at every call site, including the
 * <clinit> that still invokes them).
 */
object DptHookStripper {

    private const val ACC_STATIC = 0x0008L
    private const val ACC_SYNTHETIC = 0x1000L

    /** Hook bodies are the full reflection dance: exactly 75 code units (150 bytes). */
    private const val HOOK_BYTES = 150

    /** @return number of hook bodies neutralized. */
    fun strip(dex: ByteArray): Int {
        var count = 0
        for (cls in DexParser.parseClasses(dex)) {
            val statsFlags = (ACC_STATIC or ACC_SYNTHETIC)
            val candidates = cls.methods.filter {
                (it.accessFlags and statsFlags) == statsFlags && it.codeOff != 0L && it.insnsByteSize == HOOK_BYTES
            }
            if (candidates.isEmpty()) continue

            val invoked = HashSet<Long>()
            for (m in cls.methods) {
                if (m.codeOff == 0L || m.insnsByteSize < 6) continue
                val base = m.codeOff.toInt() + 16
                for (i in 0 until m.insnsByteSize - 5) {
                    if (dex[base + i] == 0x71.toByte() && dex[base + i + 1] == 0x00.toByte()) {
                        val midx = (dex[base + i + 2].toLong() and 0xFF) or ((dex[base + i + 3].toLong() and 0xFF) shl 8)
                        invoked.add(midx)
                    }
                }
            }

            for (c in candidates) {
                if (c.methodIdx in invoked) {
                    neutralize(dex, c)
                    count++
                }
            }
        }
        return count
    }

    /**
     * Removes the packer's direct `<clinit>` bridge glue: the app code keeps an
     * `invoke-static {} ...JniBridge.clinit()V` inserted into class initializers,
     * but the JniBridge class only existed in the packed stub dex (dropped during
     * restore), so ART throws NoClassDefFoundError the moment the class loads.
     *
     * NOPs each matching 35c invoke (method index lives at insns[i+2], 16-bit)
     * in place, keeping code items and offsets untouched. Skips dexes that
     * actually define the bridge (nothing to strip).
     *
     * @return number of bridge invokes neutralized.
     */
    fun stripBridgeCalls(dex: ByteArray, label: String = ""): Int {
        fun u16At(d: ByteArray, off: Int) =
            ((d.getOrElse(off) { 0 }.toInt() and 0xFF) or
                ((d.getOrElse(off + 1) { 0 }.toInt() and 0xFF) shl 8))
        fun u32At(d: ByteArray, off: Int) =
            (d.getOrElse(off) { 0 }.toLong() and 0xFF) or
                ((d.getOrElse(off + 1) { 0 }.toLong() and 0xFF) shl 8) or
                ((d.getOrElse(off + 2) { 0 }.toLong() and 0xFF) shl 16) or
                ((d.getOrElse(off + 3) { 0 }.toLong() and 0xFF) shl 24)
        fun mutf8At(d: ByteArray, stringIdx: Int, stringIdsOff: Int, stringIdsSize: Int): String? {
            if (stringIdx < 0 || stringIdx >= stringIdsSize) return null
            val dataOff = u32At(d, stringIdsOff + stringIdx * 4).toInt()
            if (dataOff >= d.size) return null
            var p = dataOff.toInt()
            var v = d[p++].toInt() and 0xFF
            while (v and 0x80 != 0) { v = d[p++].toInt() and 0xFF }
            val sb = StringBuilder()
            while (p < d.size) {
                val b = d[p++].toInt()
                if (b == 0) break
                sb.append(b.toChar())
            }
            return sb.toString()
        }

        if (dex.size < 0x70) return 0
        val stringIdsSize = u32At(dex, 0x38).toInt()
        val stringIdsOff = u32At(dex, 0x3C).toInt()
        val typeIdsSize = u32At(dex, 0x40).toInt()
        val typeIdsOff = u32At(dex, 0x44).toInt()
        val methodIdsSize = u32At(dex, 0x58).toInt()
        val methodIdsOff = u32At(dex, 0x5C).toInt()
        val classDefsSize = u32At(dex, 0x60).toInt()
        val classDefsOff = u32At(dex, 0x64).toInt()
        if (stringIdsOff == 0 || typeIdsOff == 0 || methodIdsOff == 0) return 0

        fun typeDesc(typeIdx: Int): String? {
            if (typeIdx < 0 || typeIdx >= typeIdsSize) return null
            val sIdx = u32At(dex, typeIdsOff + typeIdx * 4).toInt()
            return sIdx.let { mutf8At(dex, it, stringIdsOff, stringIdsSize) }
        }

        // When this dex defines a bridge class, its calls are legit; leave it alone.
        val definesBridge = (0 until classDefsSize).any { c ->
            val clsIdx = u32At(dex, classDefsOff + c * 32).toInt()
            typeDesc(clsIdx)?.contains("JniBridge") == true
        }
        if (definesBridge) return 0

        val bridgeMidx = (0 until methodIdsSize).filter { m ->
            val clsIdx = u16At(dex, methodIdsOff + m * 8)
            (clsIdx.toInt() in 0 until typeIdsSize) && typeDesc(clsIdx.toInt())?.contains("JniBridge") == true
        }.toSet()
        if (bridgeMidx.isEmpty()) return 0

        var count = 0
        val debugProbe = dex.size > 50000
        if (debugProbe) println("   stripBridgeCalls[$label] size=${dex.size} bridgeMidx=$bridgeMidx definesBridge=$definesBridge")
        for (cls in DexParser.parseClasses(dex)) {
            for (m in cls.methods) {
                if (m.codeOff == 0L || m.insnsByteSize < 6) continue
                if (debugProbe && m.codeOff == 40248L) println("   probe[$label] clinit codeOff=40248 insnsBytes=${m.insnsByteSize}")
                val base = m.codeOff.toInt() + 16
                var ins = 0
                while (ins <= m.insnsByteSize - 6) {
                    val op = dex[base + ins].toInt() and 0xFF
                    if (debugProbe && m.codeOff == 40248L && m.insnsByteSize == 68 && ins == 0) {
                        val sb = StringBuilder()
                        for (i in 0 until m.insnsByteSize) {
                            sb.append(java.lang.String.format("%02X", dex[base + i].toInt() and 0xFF))
                            if (i % 2 == 1) sb.append(' ')
                        }
                        println("   scan[$label] entry clinit bytes: " + sb)
                    }
                    if (op in 0x6E..0x72) {             // 35c invoke family
                        val cnt = (dex[base + ins + 1].toInt() ushr 4) and 0x0F
                        val midx = u16At(dex, base + ins + 2)
                        val size = 3 + maxOf(0, cnt - 5)  // 35c extra words beyond 5 args
                        if (midx in bridgeMidx) {
                            for (j in 0 until size * 2) dex[base + ins + j] = 0
                            count++
                            ins += size * 2
                            continue
                        }
                        ins += size * 2
                        continue
                    }
                    val u = insnUnits(dex, base + ins)
                    if (u <= 0) break
                    ins += u * 2
                }
            }
        }
        return count
    }

    private fun neutralize(dex: ByteArray, m: com.dpt.unpack.dex.DexMethodLite) {
        val base = m.codeOff.toInt() + 16
        dex[base] = 0x0E.toByte() // return-void
        dex[base + 1] = 0x00
        for (i in base + 2 until base + m.insnsByteSize) {
            dex[i] = 0x00
        }
    }

    /** Code-unit width of the dalvik instruction starting at insns[off]. */
    private fun insnUnits(d: ByteArray, off: Int): Int {
        val op = d.getOrElse(off) { 0 }.toInt() and 0xFF
        val cnt = (d.getOrElse(off + 1) { 0 }.toInt() ushr 4) and 0x0F
        return when (op) {
            0x00, 0x0E, 0x0F, 0x10, 0x11, 0x1D, 0x1E, 0x27, 0x28, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
            0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F -> 1 // 10x/12x/11n/11x/10t
            in 0x6E..0x72, 0x24 -> 3 + maxOf(0, cnt - 5)                                     // 35c
            in 0x74..0x78, 0x25 -> 3 + maxOf(0, cnt - 5)                                     // 3rc
            0x03, 0x06, 0x09, 0x14, 0x17, 0x18, 0x1B, 0x26, 0x2A, 0x2B, 0x2C -> if (op == 0x18) 5 else 3 // 32x/31i/51l/31t/31c/30t
            0x01, 0x04, 0x07, 0x0A, 0x0B, 0x0C, 0x0D, 0x12, 0x21, in 0xB0..0xCF -> 1       // 12x/11x/11n
            else -> 2
        }
    }
}