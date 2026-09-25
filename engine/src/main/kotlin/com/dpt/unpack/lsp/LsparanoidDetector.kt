package com.dpt.unpack.lsp

import java.io.File
import java.util.zip.ZipFile

/**
 * Detects whether an APK contains the LSParanoid string-obfuscation runtime
 * (`org.lsposed.lsparanoid.DeobfuscatorHelper`) inside any of its dex files.
 */
object LsparanoidDetector {

    private val MARKERS = listOf(
        "lsposed/lsparanoid",
        "DeobfuscatorHelper",
        "RandomHelper",
    )

    fun isLsparanoid(apk: File): Boolean {
        ZipFile(apk).use { zip ->
            for (e in zip.entries()) {
                val name = e.name
                if (!name.startsWith("classes") || !name.endsWith(".dex")) continue
                val bytes = zip.getInputStream(e).readBytes()
                if (containsMarker(bytes)) return true
            }
        }
        return false
    }

    private fun containsMarker(bytes: ByteArray): Boolean {
        // LSParanoid stores class name strings MUTF-8 encoded inside the dex string pool.
        for (marker in MARKERS) {
            val b = marker.toByteArray(Charsets.UTF_8)
            if (indexOf(bytes, b, b.size) != -1) return true
        }
        return false
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray, needleLen: Int): Int {
        outer@ for (i in 0..hay.size - needleLen) {
            for (j in 0 until needleLen) {
                if (hay[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }
}