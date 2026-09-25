package com.dpt.unpack.axml

/**
 * Binary AndroidManifest.xml (AXML) parser + surgical editor.
 *
 * AAPT2 manifest facts (verified on target APK):
 *  - the string pool is UTF-8 encoded;
 *  - every start-tag attribute `name` field is the STRING-POOL INDEX of the
 *    attribute name (e.g. "name", "appComponentFactory");
 *  - RES_XML_RESOURCE_MAP maps those pool indices -> framework resource ids;
 *  - the typed value layout is  {u16 size, u8 res0, u8 dataType, u32 data}.
 *
 * Edits used by the unpacker:
 *  - <application android:name> = shell ProxyApplication -> attribute removed;
 *  - <application android:appComponentFactory> -> restored back to the
 *    original CoreComponentFactory value (string appended to pool if needed).
 */
object AxmlManifest {

    const val TYPE_STRING_POOL = 0x0001
    const val TYPE_RESOURCE_MAP = 0x0180
    const val CHUNK_START_TAG = 0x0102

    data class Attr(
        val nsId: Long,
        val nameField: Long, // string pool index of the attribute name
        val rawValue: Long,
        val dataType: Int,
        val data: Long,
        val valueText: String,
    )

    data class StartTag(
        val chunkStart: Int,
        val chunkSize: Int,
        val nsId: Int,
        val nameId: Int,
        val attrCount: Int,
        val attrs: List<Attr>,
        val bodyOffset: Int, // absolute offset where the attribute entries begin
    )

    data class Parsed(
        val strings: List<String>,
        val stringTypeUtf8: Boolean,
        val stringPoolChunkStart: Int,
        val stringPoolHeaderSize: Int,
        val resourceMap: List<Long>,
        val startTags: List<StartTag>,
    )

    fun parse(data: ByteArray): Parsed {
        val strings = AxmlStrings.extract(data)
        var stringPoolStart = -1
        var stringPoolHeader = -1
        var utf8flag = false
        val resourceMap = mutableListOf<Long>()
        val tags = mutableListOf<StartTag>()
        var off = 8
        while (off + 8 <= data.size) {
            val type = u16(data, off) and 0xFFFF
            val headerSize = u16(data, off + 2) and 0xFFFF
            val size = u32(data, off + 4)
            if (size < 8 || off + size > data.size) break
            when (type) {
                TYPE_STRING_POOL -> {
                    stringPoolStart = off
                    stringPoolHeader = headerSize
                    utf8flag = (u32(data, off + 16) and 0x100) != 0L
                }
                TYPE_RESOURCE_MAP -> {
                    var p = off + 8
                    while (p + 4 <= off + size) {
                        resourceMap.add(u32(data, p))
                        p += 4
                    }
                }
                CHUNK_START_TAG -> {
                    if (headerSize == 0x10 && size >= 0x20) {
                        val p = off + 0x10
                        val nsId = u32(data, p).toInt()
                        val nameId = u32(data, p + 4).toInt()
                        val attrStart = u16(data, p + 8) and 0xFFFF
                        val attrCount = u16(data, p + 12) and 0xFFFF
                        val body = off + headerSize + attrStart
                        val attrs = mutableListOf<Attr>()
                        for (i in 0 until attrCount) {
                            val a = body + i * 20
                            val dType = data[a + 15].toInt() and 0xFF
                            val rawIdx = (u32(data, a + 8) and 0xFFFFFFFFL).toInt()
                            val dIdx = (u32(data, a + 16) and 0xFFFFFFFFL).toInt()
                            val nameStr = strings.getOrElse((u32(data, a + 4) and 0xFFFFFFFFL).toInt()) { "" }
                            attrs.add(
                                Attr(
                                    nsId = u32(data, a) and 0xFFFFFFFFL,
                                    nameField = u32(data, a + 4) and 0xFFFFFFFFL,
                                    rawValue = u32(data, a + 8) and 0xFFFFFFFFL,
                                    dataType = dType,
                                    data = u32(data, a + 16) and 0xFFFFFFFFL,
                                    valueText = when {
                                        dType == 0x03 -> strings.getOrElse(dIdx) { "<$dIdx>" }
                                        nameStr == "name" && dType == 0x03 -> strings.getOrElse(rawIdx) { "<$rawIdx>" }
                                        dType == 0x10 -> dIdx.toString()
                                        else -> "0x${dIdx.toString(16)}"
                                    },
                                )
                            )
                        }
                        tags.add(StartTag(off, size.toInt(), nsId, nameId, attrCount, attrs, body))
                    }
                }
            }
            off += size.toInt()
        }
        return Parsed(strings, utf8flag, stringPoolStart, stringPoolHeader, resourceMap, tags)
    }

    fun findTag(parsed: Parsed, name: String): StartTag? =
        parsed.startTags.firstOrNull { parsed.strings.getOrElse(it.nameId) { "" } == name }

    /** Remove an attribute whose NAME STRING (pool idx) equals the given one. */
    fun removeAttributeByName(data: ByteArray, tag: StartTag, attrName: String, strings: List<String>): ByteArray {
        val idx = tag.attrs.indexOfFirst { strings.getOrElse(it.nameField.toInt()) { "" } == attrName }
        if (idx < 0) return data
        val at = tag.bodyOffset + idx * 20
        if (at < 0 || at + 20 > data.size) return data
        val out = ByteArray(data.size - 20)
        System.arraycopy(data, 0, out, 0, at)
        System.arraycopy(data, at + 20, out, at, data.size - at - 20)
        reduceU16(out, tag.chunkStart + 0x1C, 1)           // attrCount
        writeU32(out, tag.chunkStart + 4, u32(out, tag.chunkStart + 4) - 20) // tag chunk size
        writeU32(out, 4, out.size.toLong())                // top-level ResChunk_header.size == file length
        return out
    }

    /** High-level restore: strip the shell <application> hook attributes. */
    fun restoreApplication(data0: ByteArray): ByteArray {
        var data = data0
        // 1. remove android:name="ProxyApplication"  (original app had none -> default Application)
        data = run {
            val parsed = parse(data)
            val app = findTag(parsed, "application")
            if (app == null) data else removeAttributeByName(data, app, "name", parsed.strings)
        }
        // 2. remove android:appComponentFactory (ProxyComponentFactory); the framework
        //    falls back to the default androidx CoreComponentFactory behaviour.
        data = run {
            val parsed = parse(data)
            val app = findTag(parsed, "application")
            if (app == null) data else removeAttributeByName(data, app, "appComponentFactory", parsed.strings)
        }
        return data
    }

    /**
     * Removes a named attribute from the first <tagName> element in a binary
     * manifest without touching the string pool (attribute entries are removed
     * from the tag body in place and the tag chunk size is shrunk).  Re-parses
     * the manifest so the attribute lookup is always against current bytes.
     */
    fun removeAttribute(data: ByteArray, tagName: String, attrName: String): ByteArray {
        val parsed = parse(data)
        val tag = findTag(parsed, tagName)
        return if (tag == null) data else removeAttributeByName(data, tag, attrName, parsed.strings)
    }

    /**
     * Sets <application android:name> to [className] in a binary manifest.
     * Appends the class string to the string pool (indices of existing strings
     * do not move), then rewrites the value of the `name` attribute (inserting
     * the attribute when the shell removed it). Used by the ArkShell pipeline to
     * point the APK back at the real Application after the 360 stub is replaced.
     */
    fun setApplicationName(data0: ByteArray, className: String): ByteArray {
        // Manifest component names must be in dotted form (android:name), while
        // ArkDexTools discovers classes in DEX slash form (com/x/Foo). Convert.
        val dotted = className.replace('/', '.')
        val p0 = parse(data0)

        val pool = p0.stringPoolChunkStart
        if (pool < 0) throw IllegalStateException("no string pool in manifest")
        val styleCount = u32(data0, pool + 12)
        if (styleCount != 0L) {
            throw IllegalStateException(
                "manifest string pool has styles ($styleCount) - unsupported for in-place edit, " +
                    "use --application with a dump rebuilt via apktool instead"
            )
        }

        // 1. rebuild the string pool with className appended -> (new bytes, new index)
        val out1 = rebuildPoolWithExtra(data0, p0, dotted)

        // 2. re-parse to get fresh absolute offsets (pool grew)
        val p1 = parse(out1)
        val app = p1.startTags.firstOrNull { p1.strings.getOrElse(it.nameId) { "" } == "application" }
            ?: throw IllegalStateException("no <application> tag in manifest")
        val nameAttr = app.attrs.indexOfFirst { p1.strings.getOrElse(it.nameField.toInt()) { "" } == "name" }

        return if (nameAttr >= 0) {
            val at = app.bodyOffset + nameAttr * 20
            val newIdx = p1.strings.size - 1
            writeU32(out1, at + 8, newIdx.toLong())  // rawValue (string pool index)
            writeU32(out1, at + 16, newIdx.toLong()) // data (string pool index)
            out1[at + 13] = 0 // res0
            out1[at + 15] = 0x03 // TYPE_STRING
            out1
        } else {
            insertStringAttribute(out1, app, "name", p1.strings.size - 1)
        }
    }

    /** Appends one string to the pool without re-encoding existing strings. */
    private fun rebuildPoolWithExtra(data: ByteArray, parsed: Parsed, extra: String): ByteArray {
        val p = parsed.stringPoolChunkStart
        val headerSize = parsed.stringPoolHeaderSize
        val count = u32(data, p + 8).toInt()
        val flags = u32(data, p + 16)
        val stringsStart = u32(data, p + 20).toInt()
        val oldChunkSize = u32(data, p + 4).toInt()
        val oldPoolEnd = p + oldChunkSize
        val utf8 = parsed.stringTypeUtf8

        // existing data (string bytes) starts at stringsStart relative to pool
        val existingDataLen = oldChunkSize - stringsStart
        val existingData = data.copyOfRange(p + stringsStart, p + oldChunkSize)
        val newStringBytes = if (utf8) encodeUtf8(extra) else encodeUtf16(extra)
        val newCount = count + 1
        // new stringsStart must leave room for newCount offsets (= newCount*4 bytes)
        val newStringsStart = headerSize + newCount * 4
        // Android requires each XML chunk's size to be a multiple of 4; the
        // appended string bytes can push the pool chunk size off that boundary,
        // which makes aapt report "XML size ... is not on an integer boundary"
        // and the whole manifest unparseable.  Pad the pool so its size is %4==0.
        val rawChunkSize = newStringsStart + existingDataLen + newStringBytes.size
        val padding = (4 - (rawChunkSize % 4)) % 4

        val out = ByteArray(p + rawChunkSize + padding + (data.size - oldPoolEnd))
        // prefix (usually just the 8-byte file header) up to the pool chunk
        System.arraycopy(data, 0, out, 0, p)
        // pool header
        writeU16(out, p, 0x0001)
        writeU16(out, p + 2, headerSize)
        writeU32(out, p + 4, (rawChunkSize + padding).toLong())
        writeU32(out, p + 8, newCount.toLong())
        writeU32(out, p + 12, 0L)
        writeU32(out, p + 16, flags)
        writeU32(out, p + 20, newStringsStart.toLong())
        writeU32(out, p + 24, 0L)
        // new offset table: old strings keep their offsets (pool data and the
        // stringsStart field shift by the same amount, so they cancel out);
        // the appended string sits right after the existing data.
        for (i in 0 until count) {
            val origOff = u32(data, p + headerSize + i * 4).toInt()
            writeU32(out, p + headerSize + i * 4, origOff.toLong())
        }
        // new string offset: relative to data-area start, so it is existingDataLen
        writeU32(out, p + headerSize + count * 4, existingDataLen.toLong())
        // data area: old data verbatim + new string (+ zero padding to 4-boundary)
        val dataOutStart = p + newStringsStart
        System.arraycopy(existingData, 0, out, dataOutStart, existingDataLen)
        System.arraycopy(newStringBytes, 0, out, dataOutStart + existingDataLen, newStringBytes.size)
        // tail (everything after the pool chunk)
        System.arraycopy(data, oldPoolEnd, out, p + rawChunkSize + padding, data.size - oldPoolEnd)
        writeU32(out, 4, out.size.toLong())
        return out
    }

    /** Inserts a fresh string attribute (e.g. android:name) into <application>. */
    private fun insertStringAttribute(data: ByteArray, app: StartTag, attrName: String, valueIdx: Int): ByteArray {
        var ns = 0L
        val out = ByteArray(data.size + 20)
        // attr name string index
        var nameIdx = 0
        run outer@{
            AxmlStrings.extract(data).forEachIndexed { i, s ->
                if (s == attrName) {
                    nameIdx = i
                    return@outer
                }
            }
            // not in pool: rebuild is required - caller guarantees presence (aapt always emits "name")
            nameIdx = -1
        }
        if (nameIdx < 0) throw IllegalStateException("attribute name '$attrName' not in string pool")
        val androidNs = AxmlStrings.extract(data).indexOf("http://schemas.android.com/apk/res/android")
        if (androidNs >= 0) ns = androidNs.toLong()

        val at = app.bodyOffset
        System.arraycopy(data, 0, out, 0, at)
        // 20-byte RES_XML_ATTRIBUTE {ns,name,rawValue,{size,res0,dataType,data}}
        writeU32(out, at, ns)
        writeU32(out, at + 4, nameIdx.toLong())
        writeU32(out, at + 8, valueIdx.toLong())
        writeU16(out, at + 12, 8)      // typed value size
        out[at + 14] = 0               // res0
        out[at + 15] = 0x03            // TYPE_STRING
        writeU32(out, at + 16, valueIdx.toLong())
        System.arraycopy(data, at, out, at + 20, data.size - at)
        writeU16(out, app.chunkStart + 0x1C, u16(out, app.chunkStart + 0x1C) + 1) // attrCount
        writeU32(out, app.chunkStart + 4, u32(out, app.chunkStart + 4) + 20)      // tag chunk size
        writeU32(out, 4, out.size.toLong())                                        // file size
        return out
    }

    private fun encodeUtf8(s: String): ByteArray {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val out = java.io.ByteArrayOutputStream()
        writeLen8(out, s.length)
        writeLen8(out, bytes.size)
        out.write(bytes)
        out.write(0) // NULL terminator
        return out.toByteArray()
    }

    private fun encodeUtf16(s: String): ByteArray {
        val n = s.length
        val out = java.io.ByteArrayOutputStream()
        writeLen16(out, n)
        for (ch in s) {
            out.write(ch.code and 0xFF)
            out.write((ch.code shr 8) and 0xFF)
        }
        out.write(0)
        out.write(0) // NULL terminator (UTF-16LE)
        return out.toByteArray()
    }

    private fun writeLen8(out: java.io.ByteArrayOutputStream, v: Int) {
        if (v < 0x80) {
            out.write(v)
        } else {
            out.write((v shr 8) or 0x80)
            out.write(v and 0xFF)
        }
    }

    private fun writeLen16(out: java.io.ByteArrayOutputStream, v: Int) {
        if (v < 0x8000) {
            out.write(v and 0xFF)
            out.write((v shr 8) and 0xFF)
        } else {
            out.write(((v shr 16) and 0x7FFF) or 0x8000)
            out.write((v shr 8) and 0xFF)
            out.write(v and 0xFF)
        }
    }

    fun dump(parsed: Parsed, data: ByteArray) {
        val poolType = if (parsed.stringTypeUtf8) "utf8" else "utf16"
        println("    string pool: ${parsed.strings.size} strings ($poolType)")
        parsed.startTags.forEach { t ->
            val tagName = parsed.strings.getOrElse(t.nameId) { "<${t.nameId}>" }
            println("    <$tagName> attrs=${t.attrCount}")
            t.attrs.forEachIndexed { i, a ->
                val rid = if (a.nameField < parsed.resourceMap.size) {
                    parsed.resourceMap[a.nameField.toInt()]
                } else a.nameField
                val attrName = parsed.strings.getOrElse(a.nameField.toInt()) { "" }
                println("      #$i name=\"$attrName\" id=0x${rid.toString(16).padStart(8, '0')} type=0x${a.dataType.toString(16)}" +
                    if (a.dataType == 0x03) " value=\"${a.valueText}\"" else " data=${a.valueText}")
            }
        }
    }

    private fun reduceU16(b: ByteArray, at: Int, by: Int) {
        writeU16(b, at, u16(b, at) - by)
    }

    fun u16(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

    fun u32(b: ByteArray, o: Int): Long =
        (b[o].toInt() and 0xFF).toLong() or
            ((b[o + 1].toInt() and 0xFF).toLong() shl 8) or
            ((b[o + 2].toInt() and 0xFF).toLong() shl 16) or
            ((b[o + 3].toInt() and 0xFF).toLong() shl 24)

    fun writeU16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v and 0xFF).toByte()
        b[o + 1] = ((v shr 8) and 0xFF).toByte()
    }

    fun writeU32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v and 0xFF).toByte()
        b[o + 1] = ((v shr 8) and 0xFF).toByte()
        b[o + 2] = ((v shr 16) and 0xFF).toByte()
        b[o + 3] = ((v shr 24) and 0xFF).toByte()
    }

    private fun le32(v: Int): ByteArray {
        val b = ByteArray(4)
        writeU32(b, 0, v.toLong() and 0xFFFFFFFFL)
        return b
    }
}