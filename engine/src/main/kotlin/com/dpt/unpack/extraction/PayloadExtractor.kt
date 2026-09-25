package com.dpt.unpack.extraction

import java.io.ByteArrayInputStream
import java.util.zip.ZipInputStream

data class ExtractedDex(val name: String, val bytes: ByteArray)

object PayloadExtractor {

    fun extractDexEntries(zipBytes: ByteArray): List<ExtractedDex> {
        val entries = mutableListOf<ExtractedDex>()
        ZipInputStream(ByteArrayInputStream(zipBytes)).use { zis ->
            var e = zis.nextEntry
            while (e != null) {
                if (!e.isDirectory) {
                    entries.add(ExtractedDex(e.name.removeSuffix("/").substringAfterLast('/'), zis.readAllBytes()))
                }
                e = zis.nextEntry
            }
        }
        entries.sortBy { it.name }
        return entries
    }
}