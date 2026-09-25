package com.dpt.unpack.rebuild

import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * Rebuilds the unpacked APK: replaces the smoke-damaged manifest, installs the
 * restored payload dexes (the ones actually produced by the restore stage), and
 * drops every DPT-Shell artifact while transparently copying all legitimate
 * resources.
 *
 * Dropped entries:
 *   - assets/OoooooOooo          (encrypted code store)
 *   - assets/d_shell_data_001    (shell config)
 *   - assets/vwwwwwvwww/...      (native shell loader)
 *   - META-INF/KEYx.{SF,RSA,MF}  (old signing block)
 *   - the original (shell) classes.dex
 *
 * Only dex files present in the patched directory are packaged; dpt junkcode /
 * injected-bridge dexes are absent there and therefore excluded automatically.
 *
 * Compression mirrors the ground-truth (apktool) rebuild: dex/manifest/resources
 * define the content but only dex/manifest stay DEFLATED while resources.arsc
 * and the tiny META-INF *.version markers are kept STORED like the reference.
 */
object ApkRebuilder {

    private val DEX_NAME = Regex("classes\\d+\\.dex")

    fun rebuild(apk: File, patchedDir: File, restoredManifest: ByteArray, out: File) {
        out.parentFile?.mkdirs()
        val drop = { name: String ->
            name == "assets/OoooooOooo" ||
                name == "assets/d_shell_data_001" ||
                name.startsWith("assets/vwwwwwvwww") ||
                name.startsWith("assets/OOooooOooo") ||
                name == "assets/OooooOOooo" ||
                name.startsWith("META-INF/")
        }

        ZipFile(apk).use { zip ->
            ZipOutputStream(out.outputStream()).use { zos ->
                zos.setLevel(9)

                // 1. AndroidManifest.xml (restored) - first entry
                putDeflated(zos, "AndroidManifest.xml", restoredManifest)

                // 2. all legit entries except shell artifacts
                val entries = zip.entries().toList()
                for (e in entries) {
                    val name = e.name
                    if (drop(name)) continue
                    if (name.startsWith("classes") && name.endsWith(".dex")) continue // old shell dex
                    if (name == "AndroidManifest.xml") continue
                    val bytes = zip.getInputStream(e).readBytes()
                    if (mustStore(name)) {
                        putStored(zos, name, bytes)
                    } else {
                        putDeflated(zos, name, bytes)
                    }
                }

                // 3. restored dexes from patched directory
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
    }

    /**
     * Entries that must be stored uncompressed so Android can open them as
     * file descriptors (MediaPlayer / AssetManager).  Android R+ requires
     * STORED + 4-byte alignment; zipalign handles the alignment.
     */
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