package com.dpt.unpack.detection

import com.dpt.unpack.axml.AxmlStrings
import java.io.File
import java.util.zip.ZipFile

/**
 * Detects a decorative ("fake") 360 Jiagu layer riding on top of another
 * protection - typically a DPT shell.  The decoy ships jiagu natives and/or
 * Art-Jiagu marker files, but nothing actually wires a 360 runtime: the
 * manifest declares no com.qihoo / com.stub / b2al component and the payload
 * dexes never reference jiagu or a 360 loader.  In that case the artifacts are
 * safe to strip from the rebuilt APK.  Any real wiring marker keeps them.
 */
data class Fake360Scan(
    /** jiagu natives / decoy-marker entries found in the input zip. */
    val candidates: List<String>,
    /** evidence that a real 360 runtime is wired (empty => decorative layer). */
    val wiring: List<String>,
) {
    val fake: Boolean get() = candidates.isNotEmpty() && wiring.isEmpty()
}

object Fake360Detector {

    /** substrings (manifest string pool) that mean a real 360 component is declared. */
    private val MANIFEST_WIRING = listOf("com.qihoo", "com.stub", "b2al", "jiagu")

    /** substrings in payload dex bytes that mean a real 360 runtime is present. */
    private val DEX_WIRING = listOf("jiagu", "com/stub/", "com/qihoo", "Lcom/stub", "Lcom/qihoo")

    /** small-file content markers that mark a planted decoy. */
    private val DECOY_MARKERS = listOf("NeoArk", "Art-Jiagu", "fake 360")

    fun scan(apk: File, manifest: ByteArray, payloadDexes: List<ByteArray>): Fake360Scan {
        val candidates = linkedSetOf<String>()

        ZipFile(apk).use { z ->
            for (e in z.entries().toList()) {
                if (e.isDirectory) continue
                val name = e.name
                if (name.substringAfterLast('/').contains("jiagu", ignoreCase = true)) {
                    candidates += name
                    continue
                }
                if (e.size in 1..4095) {
                    val head = z.getInputStream(e).use { it.readNBytes(512) }
                    val latin = String(head, Charsets.ISO_8859_1)
                    if (DECOY_MARKERS.any { latin.contains(it, ignoreCase = true) }) {
                        candidates += name
                    }
                }
            }
        }
        if (candidates.isEmpty()) return Fake360Scan(emptyList(), emptyList())

        val wiring = linkedSetOf<String>()
        for (s in AxmlStrings.extract(manifest)) {
            val low = s.lowercase()
            for (m in MANIFEST_WIRING) if (low.contains(m)) { wiring += "manifest: $s"; break }
        }
        for ((i, d) in payloadDexes.withIndex()) {
            if (d.isEmpty()) continue
            val latin = String(d, Charsets.ISO_8859_1)
            for (m in DEX_WIRING) {
                if (latin.contains(m, ignoreCase = true)) { wiring += "dex$i: references '$m'"; break }
            }
        }
        return Fake360Scan(candidates.toList(), wiring.toList())
    }
}
