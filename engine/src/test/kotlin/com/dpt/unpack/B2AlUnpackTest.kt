package com.dpt.unpack

import com.dpt.unpack.ark.ArkDexTools
import com.dpt.unpack.ark.ArkRebuilder
import com.dpt.unpack.axml.AxmlManifest
import com.dpt.unpack.b2al.B2AlDetector
import java.io.File
import java.util.zip.ZipFile
import kotlin.test.Test

class B2AlUnpackTest {

    private val testApk = File("C:\\Users\\F A H A D\\Desktop\\New folder (3)\\cackme.apk")

    @Test
    fun unpackCackme() {
        if (!testApk.exists()) { println("APK not found"); return }
        val outDir = File("C:\\Users\\F A H A D\\Desktop\\New folder (3)\\cackme-unpacked-fahad")
        outDir.deleteRecursively()
        outDir.mkdirs()

        println("[1/4] Detecting B2Al in ${testApk.name}...")
        val info = B2AlDetector.detect(testApk)
        if (!info.detected) { println("NOT detected as B2Al"); return }
        println("  carrier: ${info.carrierEntry}, records: ${info.records.size}")

        println("[2/4] Recovering ${info.records.size} DEX records...")
        val pd = File(outDir, "patched_dex").apply { mkdirs() }
        for (rec in info.records) {
            val name = if (rec.index == 1) "classes.dex" else "classes${rec.index}.dex"
            File(pd, name).writeBytes(rec.data)
            println("  $name: ${rec.data.size} bytes")
        }

        println("[3/4] Restoring Application entry point...")
        val mb = ZipFile(testApk).use { z ->
            z.getEntry("AndroidManifest.xml")?.let { z.getInputStream(it).readBytes() }
        } ?: throw IllegalStateException("no AndroidManifest.xml")
        val pdf = pd.listFiles { f, n -> n.startsWith("classes") && n.endsWith(".dex") }
            ?.sortedBy { if (it.name == "classes.dex") 0 else it.name.removePrefix("classes").removeSuffix(".dex").toInt() }
            ?.map { it.readBytes() } ?: emptyList()
        val ra = info.applicationClass ?: ArkDexTools.discoverRealApplication(null, pdf, null)
        println("  application: ${ra ?: "(none found)"}")
        val pm = if (ra != null) AxmlManifest.setApplicationName(mb, ra.replace("/", "."))
                 else AxmlManifest.removeAttribute(mb, "application", "android:name")

        println("[4/4] Rebuilding APK...")
        val fa = File(outDir, "cackme-unpacked.apk")
        ArkRebuilder.rebuild(testApk, pd, pm, fa)

        println("\nDone!")
        println("  Output: ${fa.absolutePath}")
        println("  Size: ${fa.length()} bytes")
        println("  DEX files: ${pdf.size}")
    }
}
