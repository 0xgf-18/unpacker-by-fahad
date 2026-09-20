package com.dpt.unpack.ark

import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * Rebuilds an unpacked 360-Jiagu / B2Al APK:
 *  - drops the shell's stub classes*.dex (the only thing that shipped);
 *  - installs the recovered payload dexes;
 *  - drops old signing blocks;
 *  - writes the manifest with the real <application android:name>;
 *  - scrubs the packer's native decrypt stubs (libB2alStub / libArkStub /
 *    libJiagu), which are dead weight once the payload dex is present and are
 *    never referenced by the recovered code (verified against the app dex);
 *  - keeps every resource / asset / native lib - assets .so files in particular
 *    are often the app's OWN runtime engine, never strip them;
 *  - returns the list of scrubbed entry names.
 */
object ArkRebuilder {

    private val DEX_NAME = Regex("classes\\d+\\.dex")

    fun rebuild(apk: File, patchedDir: File, manifest: ByteArray, out: File): List<String> {
        out.parentFile?.mkdirs()
        val scrubbed = ArrayList<String>()
        val dropSig = { name: String ->
            name.startsWith("META-INF/") && (name.endsWith(".MF") ||
                name.endsWith(".SF") || name.endsWith(".RSA") || name.endsWith(".DSA") ||
                name.endsWith(".EC") || name.contains("CERT"))
        }

        ZipFile(apk).use { zip ->
            ZipOutputStream(out.outputStream()).use { zos ->
                zos.setLevel(9)

                putDeflated(zos, "AndroidManifest.xml", manifest)

                val entries = zip.entries().toList()
                for (e in entries) {
                    val name = e.name
                    if (name == "AndroidManifest.xml") continue
                    if (name == "META-INF/MANIFEST.MF") continue
                    if (name.startsWith("classes") && name.endsWith(".dex")) continue // old shell stub
                    if (dropSig(name)) continue
                    if (isPackerStubLib(name)) {
                        scrubbed.add("$name (${e.size} B)")
                        continue
                    }
                    val bytes = zip.getInputStream(e).readBytes()
                    if (mustStore(name)) {
                        putStored(zos, name, bytes)
                    } else {
                        putDeflated(zos, name, bytes)
                    }
                }

                val dexFiles = patchedDir.listFiles { f ->
                    f.isFile && (f.name == "classes.dex" || f.name.matches(DEX_NAME))
                }?.sortedBy { f ->
                    if (f.name == "classes.dex") 0
                    else f.name.removePrefix("classes").removeSuffix(".dex").toInt()
                } ?: emptyList()
                for (f in dexFiles) {
                    putDeflated(zos, f.name, f.readBytes())
                }
            }
        }
        return scrubbed
    }

    private fun isPackerStubLib(name: String): Boolean =
        name.startsWith("lib/") && name.endsWith(".so") &&
            (name.contains("B2alStub") || name.contains("ArkStub") || name.contains("JiaguStub"))

    private fun mustStore(name: String): Boolean =
        name == "resources.arsc" ||
            name.startsWith("res/raw/") ||
            name.startsWith("assets/") ||
            (name.startsWith("META-INF/") && name.endsWith(".version"))

    private fun putStored(zos: ZipOutputStream, name: String, bytes: ByteArray) {
        val entry = ZipEntry(name)
        entry.time = 0L
        entry.method = ZipEntry.STORED
        val crc = CRC32()
        crc.update(bytes)
        entry.size = bytes.size.toLong()
        entry.compressedSize = bytes.size.toLong()
        entry.crc = crc.value
        zos.putNextEntry(entry)
        zos.write(bytes)
        zos.closeEntry()
    }

    private fun putDeflated(zos: ZipOutputStream, name: String, bytes: ByteArray) {
        val entry = ZipEntry(name)
        entry.time = 0L
        entry.method = ZipEntry.DEFLATED
        zos.putNextEntry(entry)
        zos.write(bytes)
        zos.closeEntry()
    }
}