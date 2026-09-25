package com.dpt.unpack.dex

import com.dpt.unpack.util.Cursor

data class DexHeader(
    val fileSize: Long,
    val stringIdsSize: Long,
    val stringIdsOff: Long,
    val typeIdsOff: Long,
    val protoIdsSize: Long,
    val protoIdsOff: Long,
    val methodIdsSize: Long,
    val methodIdsOff: Long,
    val classDefsSize: Long,
    val classDefsOff: Long,
)

data class MethodCode(val methodIdx: Long, val codeOff: Long, val insnsByteSize: Int)

data class DexMethodLite(
    val methodIdx: Long,
    val accessFlags: Long,
    val codeOff: Long,
    val insnsByteSize: Int,
)

data class DexClassMethods(val methods: List<DexMethodLite>)

data class DexMethodInfo(
    val methodIdx: Long,
    val accessFlags: Long,
    val codeOff: Long,
    val insnsByteSize: Int,
    val name: String?,
    val shorty: String?,
)

object DexParser {

    fun parseHeader(dex: ByteArray): DexHeader {
        val c = Cursor(dex)
        c.seek(0x38)
        val stringIdsSize = c.u32()
        val stringIdsOff = c.u32()
        c.seek(0x44)
        val typeIdsOff = c.u32()
        c.seek(0x48)
        val protoIdsSize = c.u32()
        val protoIdsOff = c.u32()
        c.seek(0x58)
        val methodIdsSize = c.u32()
        val methodIdsOff = c.u32()
        c.seek(0x60)
        val classDefsSize = c.u32()
        val classDefsOff = c.u32()
        return DexHeader(
            fileSize = 0L,
            stringIdsSize = stringIdsSize,
            stringIdsOff = stringIdsOff,
            typeIdsOff = typeIdsOff,
            protoIdsSize = protoIdsSize,
            protoIdsOff = protoIdsOff,
            methodIdsSize = methodIdsSize,
            methodIdsOff = methodIdsOff,
            classDefsSize = classDefsSize,
            classDefsOff = classDefsOff,
        )
    }

    fun stringAt(dex: ByteArray, idx: Long): String? {
        val h = parseHeader(dex)
        if (idx < 0 || idx >= h.stringIdsSize) return null
        val c = Cursor(dex)
        c.seek(h.stringIdsOff.toInt() + idx.toInt() * 4)
        val dataOff = c.u32().toInt()
        c.seek(dataOff)
        val utf16Len = c.uleb128().toInt()
        return c.readBytes(utf16Len).toString(Charsets.UTF_8)
    }

    fun methodName(dex: ByteArray, methodIdx: Long): String? {
        val h = parseHeader(dex)
        if (methodIdx < 0 || methodIdx >= h.methodIdsSize) return null
        val c = Cursor(dex)
        c.seek(h.methodIdsOff.toInt() + methodIdx.toInt() * 12)
        c.skip(8)
        return stringAt(dex, c.u32())
    }

    fun methodShorty(dex: ByteArray, methodIdx: Long): String? {
        val h = parseHeader(dex)
        if (methodIdx < 0 || methodIdx >= h.methodIdsSize) return null
        val c = Cursor(dex)
        c.seek(h.methodIdsOff.toInt() + methodIdx.toInt() * 12)
        c.skip(4)
        val protoIdx = c.u32()
        if (protoIdx < 0 || protoIdx >= h.protoIdsSize) return null
        c.seek(h.protoIdsOff.toInt() + protoIdx.toInt() * 12)
        return stringAt(dex, c.u32())
    }

    fun parseMethods(dex: ByteArray): List<MethodCode> {
        val header = parseHeader(dex)
        val out = mutableListOf<MethodCode>()
        val c = Cursor(dex)
        for (i in 0 until header.classDefsSize.toInt()) {
            c.seek(header.classDefsOff.toInt() + i * 32)
            c.skip(6 * 4)
            val classDataOff = c.u32()
            if (classDataOff == 0L) continue
            parseClassData(dex, classDataOff.toInt(), out)
        }
        return out
    }

    fun parseClasses(dex: ByteArray): List<DexClassMethods> {
        val header = parseHeader(dex)
        val out = mutableListOf<DexClassMethods>()
        val c = Cursor(dex)
        for (i in 0 until header.classDefsSize.toInt()) {
            c.seek(header.classDefsOff.toInt() + i * 32)
            c.skip(6 * 4)
            val classDataOff = c.u32()
            if (classDataOff == 0L) {
                out.add(DexClassMethods(emptyList()))
                continue
            }
            out.add(parseClassLite(dex, classDataOff.toInt()))
        }
        return out
    }

    private fun parseClassLite(dex: ByteArray, classDataOff: Int): DexClassMethods {
        val c = Cursor(dex)
        c.seek(classDataOff)
        val staticFields = c.uleb128()
        val instanceFields = c.uleb128()
        val directMethods = c.uleb128()
        val virtualMethods = c.uleb128()

        for (i in 0 until (staticFields + instanceFields)) {
            c.uleb128()
            c.uleb128()
        }

        val methods = mutableListOf<DexMethodLite>()

        var prev = 0L
        for (i in 0 until directMethods) {
            prev += c.uleb128()
            val access = c.uleb128()
            val codeOff = c.uleb128()
            val insns = if (codeOff != 0L) readInsnsByteSize(dex, codeOff.toInt()) else 0
            methods.add(DexMethodLite(prev, access, codeOff, insns))
        }

        prev = 0L
        for (i in 0 until virtualMethods) {
            prev += c.uleb128()
            val access = c.uleb128()
            val codeOff = c.uleb128()
            val insns = if (codeOff != 0L) readInsnsByteSize(dex, codeOff.toInt()) else 0
            methods.add(DexMethodLite(prev, access, codeOff, insns))
        }
        return DexClassMethods(methods)
    }

    fun parseMethodsDetailed(dex: ByteArray): List<DexMethodInfo> {
        val header = parseHeader(dex)
        val out = mutableListOf<DexMethodInfo>()
        val c = Cursor(dex)
        for (i in 0 until header.classDefsSize.toInt()) {
            c.seek(header.classDefsOff.toInt() + i * 32)
            c.skip(6 * 4)
            val classDataOff = c.u32()
            if (classDataOff == 0L) continue
            parseClassDataDetailed(dex, classDataOff.toInt(), out)
        }
        return out
    }

    private fun parseClassDataDetailed(dex: ByteArray, classDataOff: Int, out: MutableList<DexMethodInfo>) {
        val c = Cursor(dex)
        c.seek(classDataOff)
        val staticFields = c.uleb128()
        val instanceFields = c.uleb128()
        val directMethods = c.uleb128()
        val virtualMethods = c.uleb128()

        for (i in 0 until (staticFields + instanceFields)) {
            c.uleb128()
            c.uleb128()
        }

        var prev = 0L
        for (i in 0 until directMethods) {
            prev += c.uleb128()
            val access = c.uleb128()
            val codeOff = c.uleb128()
            val insns = if (codeOff != 0L) readInsnsByteSize(dex, codeOff.toInt()) else 0
            out.add(DexMethodInfo(prev, access, codeOff, insns, methodName(dex, prev), methodShorty(dex, prev)))
        }

        prev = 0L
        for (i in 0 until virtualMethods) {
            prev += c.uleb128()
            val access = c.uleb128()
            val codeOff = c.uleb128()
            val insns = if (codeOff != 0L) readInsnsByteSize(dex, codeOff.toInt()) else 0
            out.add(DexMethodInfo(prev, access, codeOff, insns, methodName(dex, prev), methodShorty(dex, prev)))
        }
    }

    private fun parseClassData(dex: ByteArray, classDataOff: Int, out: MutableList<MethodCode>) {
        val c = Cursor(dex)
        c.seek(classDataOff)
        val staticFields = c.uleb128()
        val instanceFields = c.uleb128()
        val directMethods = c.uleb128()
        val virtualMethods = c.uleb128()

        for (i in 0 until (staticFields + instanceFields)) {
            c.uleb128()
            c.uleb128()
        }

        var prev = 0L
        for (i in 0 until directMethods) {
            prev += c.uleb128()
            c.uleb128()
            val codeOff = c.uleb128()
            if (codeOff != 0L) {
                out.add(MethodCode(prev, codeOff, readInsnsByteSize(dex, codeOff.toInt())))
            }
        }

        prev = 0L
        for (i in 0 until virtualMethods) {
            prev += c.uleb128()
            c.uleb128()
            val codeOff = c.uleb128()
            if (codeOff != 0L) {
                out.add(MethodCode(prev, codeOff, readInsnsByteSize(dex, codeOff.toInt())))
            }
        }
    }

    private fun readInsnsByteSize(dex: ByteArray, codeOff: Int): Int {
        val c = Cursor(dex)
        c.seek(codeOff)
        c.skip(12)
        val insnsSize = c.u32()
        return insnsSize.toInt() * 2
    }
}