package com.dpt.unpack.ark

import com.dpt.unpack.axml.AxmlManifest
import com.dpt.unpack.util.Cursor
import java.io.File
import java.util.zip.ZipFile

/**
 * Detection + manifest introspection for 360 Qihoo "Jiagu"/ArkShell packed APKs:
 *  - the real payload dexes only exist at runtime in /data/data/<pkg>/code_cache/ark_*;
 *  - the shipped classes.dex is a small proxy stub (b2al.*) that decrypts them;
 *  - the <application android:name> points at the b2al stub, never the real app.
 */
data class ArkInfo(
    val detected: Boolean,
    val reasons: List<String>,
    val packageName: String?,
    val applicationName: String?,
    val launcherActivity: String?,
    val stubDex: ByteArray?,
    val manifest: ByteArray?,
)

object ArkDetector {

    private val DEX_MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0A)
    private val STUB_PREFIXES = listOf("b2al", "com.qihoo.", "com.stub.StubApp", "com.jiagu", "arm")

    fun detect(apk: File): ArkInfo {
        ZipFile(apk).use { zip ->
            val reasons = mutableListOf<String>()
            val entries = zip.entries().asSequence().map { it.name }.toList()

            val stubEntry = zip.getEntry("classes.dex")
            if (stubEntry == null) {
                return ArkInfo(false, listOf("no classes.dex"), null, null, null, null, null)
            }
            val stubDex = zip.getInputStream(stubEntry).readAllBytes()
            if (stubDex.size < 8 || !DEX_MAGIC.indices.all { DEX_MAGIC[it] == stubDex[it] }) {
                return ArkInfo(false, listOf("classes.dex has no dex magic"), null, null, null, null, null)
            }

            val manifestBytes = zip.getEntry("AndroidManifest.xml")?.let { zip.getInputStream(it).readAllBytes() }

            // 1) textual markers
            val stubText = String(stubDex, Charsets.UTF_8)
            if (hasMarker(stubText, "b2al")) reasons.add("stub dex contains 'b2al' class-prefix (ArkShell/360 shell)")
            if (stubText.contains("StubApp")) reasons.add("stub dex contains StubApp pattern")

            // 2) asset / lib markers
            val libMarkers = entries.filter {
                it.endsWith(".a") && it.contains("jiagu") ||
                    it.endsWith(".so") && it.contains("jiagu") ||
                    it.endsWith(".so") && it.contains("apkprotect") ||
                    it.endsWith(".so") && it.contains("shell")
            }
            if (libMarkers.isNotEmpty()) reasons.add("native shell artifacts: ${libMarkers.joinToString { it.substringAfterLast('/') }}")

            // 3) manifest introspection
            val (pkg, appName, launcher) = introspectManifest(manifestBytes)

            if (appName != null && STUB_PREFIXES.any { appName.startsWith(it, ignoreCase = true) }) {
                reasons.add("<application android:name> = '$appName' (shell proxy Application)")
            } else if (appName == null) {
                reasons.add("<application> has no android:name attribute")
            }

            val detected = hasMarker(stubText, "b2al") || libMarkers.isNotEmpty()
            reasons.add(if (detected) "=> 360 Jiagu / ArkShell detected" else "=> not a recognizable 360 shell fingerprint")
            return ArkInfo(detected, reasons, pkg, appName, launcher, stubDex, manifestBytes)
        }
    }

    private fun hasMarker(text: String, needle: String) = text.contains(needle, ignoreCase = true)

    private fun introspectManifest(data: ByteArray?): Triple<String?, String?, String?> {
        if (data == null) return Triple(null, null, null)
        val parsed = try {
            AxmlManifest.parse(data)
        } catch (e: Exception) {
            return Triple(null, null, null)
        }
        var pkg: String? = null
        var appCls: String? = null
        var launcher: String? = null
        var firstActivity: String? = null

        for (t in parsed.startTags) {
            val name = parsed.strings.getOrElse(t.nameId) { "" }
            when (name) {
                "manifest" -> pkg = t.attrs.firstOrNull { parsed.strings.getOrElse(it.nameField.toInt()) { "" } == "package" }?.valueText
                "application" -> appCls = t.attrs.firstOrNull { parsed.strings.getOrElse(it.nameField.toInt()) { "" } == "name" }?.valueText
                "activity" -> {
                    val myName = t.attrs.firstOrNull { parsed.strings.getOrElse(it.nameField.toInt()) { "" } == "name" }?.valueText
                    if (myName != null) {
                        if (firstActivity == null) firstActivity = myName
                        if (hasMainLauncher(parsed, t)) launcher = myName
                    }
                }
            }
        }
        return Triple(pkg, appCls, launcher ?: firstActivity)
    }

    /** Inspects following start-tags for intent-filter action=MAIN + category=LAUNCHER. */
    private fun hasMainLauncher(parsed: AxmlManifest.Parsed, activity: AxmlManifest.StartTag): Boolean {
        val tagNames = parsed.startTags.toList()
        val idx = tagNames.indexOfFirst { it.chunkStart == activity.chunkStart }
        if (idx < 0) return false
        var main = false
        var launcher = false
        for (j in idx + 1 until tagNames.size) {
            val t = tagNames[j]
            val n = parsed.strings.getOrElse(t.nameId) { "" }
            if (n in listOf("activity", "activity-alias", "service", "receiver", "provider")) break
            when (n) {
                "action" -> {
                    val v = t.attrs.firstOrNull { parsed.strings.getOrElse(it.nameField.toInt()) { "" } == "name" }?.valueText
                    if (v == "android.intent.action.MAIN") main = true
                }
                "category" -> {
                    val v = t.attrs.firstOrNull { parsed.strings.getOrElse(it.nameField.toInt()) { "" } == "name" }?.valueText
                    if (v == "android.intent.category.LAUNCHER") launcher = true
                }
            }
        }
        return main && launcher
    }
}