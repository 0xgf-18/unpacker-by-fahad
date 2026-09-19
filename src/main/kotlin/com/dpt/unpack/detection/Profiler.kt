package com.dpt.unpack.detection

import com.dpt.unpack.b2al.B2AlDetector
import java.io.File
import java.util.zip.ZipFile

/**
 * Static protection profiler.  Scans a single APK for the fingerprints of every
 * known commercial packer / protector / runtime-obfuscator, then reports the
 * layers found (oldest -> newest scan order, strongest first) so the CLI can
 * pick the matching unpacker strategy.
 *
 * Each fingerprint is matched across four scopes:
 *  - dexString : substring found in any classes*.dex bytes (Latin-1 scan)
 *  - nativeLib : basename pattern matched against lib entries ending in .so
 *  - asset     : entry-name pattern matched against the zip entry list
 *  - manifest  : substring found in AndroidManifest.xml bytes (binary-safe)
 *
 * Scoring is additive: every unique marker hit adds to `hits`; `likelihood`
 * is a monotone transform so a single weak hit lands ~0.45 and several cross
 * scope hits saturate near 1.0.
 */
object Profiler {

    data class Layer(
        val id: String,
        val name: String,
        val kind: String,        // PACKER | PROTECTOR | OBFUSCATOR | RUNTIME
        val strategy: String,    // owned DPT pipeline id or external tool family
        val tool: String?,       // vendored repo suggestion when strategy != owned
        val hits: Int,
        val likelihood: Double,
        val evidence: List<String>,
    )

    data class Profile(
        val packageName: String?,
        val applicationCls: String?,
        val launcherActivity: String?,
        val nativeLibs: List<String>,
        val layers: List<Layer>,
        val junkSuspects: List<String>,
    )

    private data class Fingerprint(
        val id: String,
        val name: String,
        val kind: String,
        val strategy: String,
        val tool: String?,
        val dex: List<String> = emptyList(),
        val native: List<String> = emptyList(),
        val asset: List<String> = emptyList(),
        val manifest: List<String> = emptyList(),
        // Discriminative markers: a layer is only reported when at least one
        // anchor matches in the dex/native/asset scopes. Generic markers
        // (e.g. "com.qihoo", "StubApplication") stay in the scope lists to add
        // confidence weight but cannot trigger a false positive on their own.
        val anchors: List<String> = emptyList(),
        // A precise binary gate (raw classes*.dex buffers). When present it
        // replaces the text-anchor requirement and the layer is only reported
        // when the gate actually validates (e.g. a decodable B2Al record chain).
        val gate: ((List<ByteArray>) -> Boolean)? = null,
    )

    private val FINGERPRINTS = listOf(
        // --- owned DPT pipelines first ---
        Fingerprint(
            id = "b2al", name = "B2Al proxy packer", kind = "PACKER",
            strategy = "b2al", tool = null,
            dex = listOf("b2al"),
            manifest = listOf("b2al", "b2al.encryp"),
            anchors = listOf("b2al"),
            gate = { buffers -> B2AlDetector.isCarrierAmong(buffers) },
        ),
        Fingerprint(
            id = "ark360", name = "360 Qihoo Jiagu / ArkShell", kind = "PACKER",
            strategy = "ark", tool = null,
            dex = listOf("b2al", "com.qihoo", "StubApplication", "StubApp", "libjiagu"),
            native = listOf("libjiagu", "libprotectclass"),
            manifest = listOf("b2al", "com.qihoo.", "com.stub."),
            anchors = listOf("b2al", "libjiagu", "StubApp"),
        ),
        Fingerprint(
            id = "dpt", name = "DPT Shell", kind = "PACKER",
            strategy = "dpt", tool = null,
            asset = listOf("OoooooOooo", "d_shell_data_001"),
            dex = listOf("d_shell"),
            anchors = listOf("OoooooOooo", "d_shell_data_001", "d_shell"),
        ),
        Fingerprint(
            id = "lsparanoid", name = "LSParanoid (string obfuscator)", kind = "OBFUSCATOR",
            strategy = "lsparanoid", tool = null,
            dex = listOf("org.lsposed.lsparanoid", "DeobfuscatorHelper", "RandomHelper"),
            anchors = listOf("org.lsposed.lsparanoid", "DeobfuscatorHelper", "RandomHelper"),
        ),
        // --- packers needing a runtime (frida) dump backend ---
        Fingerprint(
            id = "bangcle", name = "Bangcle / SecNeo (梆梆)", kind = "PACKER",
            strategy = "frida", tool = "KeyDive",
            dex = listOf("com.secneo", "SecShell", "BangcleHelper"),
            native = listOf("libsecexe", "libsecmain", "libDexHelper"),
            manifest = listOf("com.secneo."),
            anchors = listOf("com.secneo", "SecShell", "libsecexe", "libsecmain"),
        ),
        Fingerprint(
            id = "legu", name = "Tencent Legu (腾讯乐固)", kind = "PACKER",
            strategy = "frida", tool = "KeyDive",
            dex = listOf("com.tencent.StubShell", "TxAppEntry", "StubApplication"),
            native = listOf("libshella", "libshellx", "libshellm"),
            asset = listOf("libshella", "libshellx", "libshellm"),
            manifest = listOf("com.tencent.StubShell", "com.tencent.a.a"),
            anchors = listOf("com.tencent.StubShell", "TxAppEntry", "libshella", "libshellx", "libshellm", "com.tencent.a.a"),
        ),
        Fingerprint(
            id = "ijiami", name = "Ijiami (爱加密)", kind = "PACKER",
            strategy = "frida", tool = "KeyDive",
            dex = listOf("com.ishowed.dog.shell", "com.shell.SuperApplication", "DexShell"),
            manifest = listOf("com.ishowed.dog.shell", "com.shell.SuperApplication"),
            anchors = listOf("com.ishowed.dog.shell", "DexShell"),
        ),
        Fingerprint(
            id = "baidu", name = "Baidu Protect (百度加固)", kind = "PACKER",
            strategy = "frida", tool = "KeyDive",
            dex = listOf("com.baidu.protect", "StubApplication"),
            native = listOf("libbaiduprotect", "libprotectclass"),
            manifest = listOf("com.baidu.protect"),
            anchors = listOf("com.baidu.protect", "libbaiduprotect"),
        ),
        Fingerprint(
            id = "apkprotect", name = "APKProtect (apkprotect.com)", kind = "PACKER",
            strategy = "frida", tool = "KeyDive",
            native = listOf("libapkprotect"),
            dex = listOf("com.sw.asecure.", "com.android.force."),
            manifest = listOf("com.sw.asecure."),
            anchors = listOf("libapkprotect", "com.sw.asecure.", "com.android.force."),
        ),
        Fingerprint(
            id = "dexprotector", name = "DexProtector (dexprotector.com)", kind = "PACKER",
            strategy = "frida", tool = "KeyDive",
            dex = listOf("dexprotector", "com.dexprotector"),
            native = listOf("libdexprotector"),
            anchors = listOf("com.dexprotector", "libdexprotector"),
        ),
        Fingerprint(
            id = "appkiller", name = "AppKiller Protector", kind = "PROTECTOR",
            strategy = "frida", tool = "KeyDive",
            dex = listOf("com.zsonstarcat", "app_killer"),
            anchors = listOf("com.zsonstarcat", "app_killer"),
        ),
        // --- PairipProtect (commercial dex virtualizer, needs RePairip) ---
        Fingerprint(
            id = "pairip", name = "PairipProtect (라이선스 / VM)", kind = "PACKER",
            strategy = "pairip", tool = "RePairip.jar",
            native = listOf("libpairipcore"),
            dex = listOf(
                "Lcom/pairip/VMRunner",
                "Lcom/pairip/application/Application",
                "Lcom/pairip/licensecheck3/LicenseClientV3",
                "Lcom/pairip/licensecheck",
                "Lcom/pairip/StartupLauncher",
            ),
            manifest = listOf("com.pairip.VMRunner", "com.pairip.application.Application", "com.pairip.StartupLauncher"),
            anchors = listOf("libpairipcore", "Lcom/pairip/VMRunner", "Lcom/pairip/StartupLauncher"),
        ),
        // --- framework runtimes with specialised unpackers ---
        Fingerprint(
            id = "il2cpp", name = "Unity IL2CPP", kind = "RUNTIME",
            strategy = "il2cpp", tool = "Auto-Il2cppDumper",
            native = listOf("libil2cpp"),
            asset = listOf("bin/Data/Managed/Metadata/global-metadata.dat"),
            anchors = listOf("libil2cpp", "global-metadata.dat"),
        ),
        Fingerprint(
            id = "xamarin", name = "Xamarin / .NET (Mono)", kind = "RUNTIME",
            strategy = "xamarin", tool = "pyxamstore",
            native = listOf("libmonodroid", "libmono", "libxamarin"),
            asset = listOf("assemblies/", "libmonodroid"),
            anchors = listOf("libmonodroid", "assemblies/"),
        ),
        Fingerprint(
            id = "hermes", name = "React Native (Hermes bytecode)", kind = "RUNTIME",
            strategy = "hermes", tool = "hermes_rs",
            native = listOf("libhermes"),
            asset = listOf("index.android.bundle"),
            anchors = listOf("libhermes"),
        ),
        Fingerprint(
            id = "flutter", name = "Flutter (Dart AOT)", kind = "RUNTIME",
            strategy = "flutter", tool = "blutter",
            native = listOf("libflutter", "libapp"),
            asset = listOf("flutter_assets/"),
            anchors = listOf("flutter_assets/", "libflutter"),
        ),
        // --- native-level transforms ---
        Fingerprint(
            id = "dex2c", name = "Dex2C (native method compile)", kind = "OBFUSCATOR",
            strategy = "native", tool = "d2c",
            native = listOf("dex2c", "d2c", "j2c"),
            dex = listOf("com.dex2c"),
            anchors = listOf("com.dex2c", "dex2c"),
        ),
    )

    private val JUNK_PATTERNS = listOf(
        "O0O0O0", "00O0o", "0OO0", "l1l1", "Ll1I",
        "o0O0o", "OoOoO", "0o0o", "Il1I",
    )

    fun analyze(apk: File): Profile {
        ZipFile(apk).use { zip ->
            val entries = zip.entries().asSequence().map { it.name }.toList()
            val nativeLibs = entries
                .filter { it.contains("lib/") && it.endsWith(".so") }
                .map { it.substringAfterLast('/') }
            val manifestBytes = zip.getEntry("AndroidManifest.xml")
                ?.let { zip.getInputStream(it).readAllBytes() }

            // Collect dex texts once; big dexes share one scan pass. The raw
            // buffers are kept for fingerprints that carry a binary gate.
            val dexBuffers = entries
                .filter { it.startsWith("classes") && it.endsWith(".dex") }
                .mapNotNull { e -> zip.getEntry(e)?.let { zip.getInputStream(it).readAllBytes() } }
            val dexTexts = dexBuffers.map { toLatin1(it) }

            val manifestText = manifestBytes?.let { toLatin1(it) } ?: ""

val layers = mutableListOf<Layer>()
            for (fp in FINGERPRINTS) {
                val hits = mutableListOf<String>()
                if (fp.dex.isNotEmpty()) {
                    val found = fp.dex.filter { m -> dexTexts.any { d -> d.contains(m, ignoreCase = true) } }
                    found.forEach { hits.add("dex marker: $it") }
                }
                if (fp.native.isNotEmpty()) {
                    val found = nativeLibs.filter { l -> fp.native.any { it.contains(l, ignoreCase = true) } }
                    found.forEach { hits.add("native lib: $it") }
                }
                if (fp.asset.isNotEmpty()) {
                    val found = entries.filter { e -> fp.asset.any { e.contains(it, ignoreCase = true) } }.take(4)
                    found.forEach { hits.add("entry: $it") }
                }
                if (fp.manifest.isNotEmpty()) {
                    fp.manifest.filter { manifestText.contains(it, ignoreCase = true) }.forEach { hits.add("manifest: $it") }
                }
                // Gate: a precise binary check replaces the text-anchor test
                // (the B2Al carrier is a dex blob whose chain either decodes or not).
                val gateOk = fp.gate?.invoke(dexBuffers) ?: true
                val anchorOk = fp.anchors.isEmpty() ||
                    fp.gate != null ||
                    fp.anchors.any { a ->
                        dexTexts.any { it.contains(a, ignoreCase = true) } ||
                            nativeLibs.any { it.contains(a, ignoreCase = true) } ||
                            entries.any { it.contains(a, ignoreCase = true) }
                    }
                if (gateOk && anchorOk) {
                    if (fp.gate != null && hits.isEmpty()) {
                        hits.add("gate: decodable record chain in classes*.dex")
                    }
                    if (hits.isNotEmpty()) {
                        layers.add(
                            Layer(
                                id = fp.id, name = fp.name, kind = fp.kind,
                                strategy = fp.strategy, tool = fp.tool,
                                hits = hits.size, likelihood = likelihood(hits.size),
                                evidence = hits,
                            )
                        )
                    }
                }
            }
            layers.sortByDescending { it.likelihood }

            // A real B2Al chain also matches the "b2al" text markers of the 360
            // Ark fingerprint; the precise chain gate already decided it, so drop
            // the ark layer (its runtime dump route would mis-handle this packer).
            if (layers.any { it.id == "b2al" }) layers.removeAll { it.id == "ark360" }

            // Decoy scan: "fake 360" placeholders (tiny text libjiagu*.a, Art-Jiagu
            // NeoArk markers) and SignatureKiller re-packs (real app embedded as
            // origin.apk). Proven fake-360 shell suppressed; ark strategy dropped.
            val decoyHits = scanDecoys(zip, entries)
            if (decoyHits.isNotEmpty()) {
                val contentProof = decoyHits.any { it.startsWith("placeholder native") || it.startsWith("decoy marker") }
                if (contentProof) layers.removeAll { it.id == "ark360" }
                layers.add(
                    Layer(
                        id = "fake360",
                        name = if (contentProof) "Fake 360 decoy (Art-Jiagu NeoArk / SignatureKiller re-pack)"
                               else "SignatureKiller re-pack (embedded app)",
                        kind = "DECOY", strategy = "embedded", tool = null,
                        hits = decoyHits.size, likelihood = 1.0, evidence = decoyHits,
                    )
                )
                layers.sortByDescending { it.likelihood }
            }

            val junkSuspects = if (dexTexts.isNotEmpty()) {
                val text = dexTexts.joinToString("\u0000")
                JUNK_PATTERNS.mapNotNull { p ->
                    val n = countOccurrences(text, p)
                    if (n >= 20) "junk-name pattern '$p' (${n} hits)" else null
                }
            } else emptyList()

            val (pkg, appCls, launcher) = introspectManifest(manifestBytes)

            return Profile(pkg, appCls, launcher, nativeLibs.sorted(), layers, junkSuspects)
        }
    }

    fun bestStrategy(profile: Profile, owned: Set<String>): String? {
        val ownedLayer = profile.layers.firstOrNull { it.strategy in owned }
        return ownedLayer?.strategy
    }

    /** Layers that the CLI currently owns a pipeline for. */
    fun ownedStrategies(): Set<String> = setOf("dpt", "lsparanoid", "ark", "b2al")

    fun isRawApk(profile: Profile): Boolean = profile.layers.isEmpty() && profile.junkSuspects.isEmpty()

    private fun likelihood(hits: Int): Double = if (hits <= 0) 0.0 else minOf(1.0, 0.42 + 0.16 * (hits - 1))

    private fun countOccurrences(hay: String, needle: String): Int {
        if (needle.isEmpty()) return 0
        var n = 0
        var i = 0
        while (true) {
            i = hay.indexOf(needle, i, ignoreCase = true)
            if (i < 0) break
            n++
            i += needle.length
        }
        return n
    }

    private fun introspectManifest(data: ByteArray?): Triple<String?, String?, String?> {
        if (data == null) return Triple(null, null, null)
        val parsed = try { com.dpt.unpack.axml.AxmlManifest.parse(data) } catch (e: Exception) { return Triple(null, null, null) }
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
                        if (launcher == null) {
                            // quick launcher heuristic: current activity right before MAIN/LAUNCHER intent
                            val tags = parsed.startTags.toList()
                            val idx = tags.indexOfFirst { it.chunkStart == t.chunkStart }
                            if (idx >= 0) {
                                var main = false; var cat = false
                                for (j in idx + 1 until tags.size) {
                                    val tt = tags[j]
                                    val n = parsed.strings.getOrElse(tt.nameId) { "" }
                                    if (n in listOf("activity", "activity-alias", "service", "receiver", "provider")) break
                                    when (n) {
                                        "action" -> { val v = tt.attrs.firstOrNull { parsed.strings.getOrElse(it.nameField.toInt()) { "" } == "name" }?.valueText; if (v == "android.intent.action.MAIN") main = true }
                                        "category" -> { val v = tt.attrs.firstOrNull { parsed.strings.getOrElse(it.nameField.toInt()) { "" } == "name" }?.valueText; if (v == "android.intent.category.LAUNCHER") cat = true }
                                    }
                                }
                                if (main && cat) launcher = myName
                            }
                        }
                    }
                }
            }
        }
        return Triple(pkg, appCls, launcher ?: firstActivity)
    }

    private fun toLatin1(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size)
        for (b in bytes) sb.append((b.toInt() and 0xFF).toChar())
        return sb.toString()
    }

    /**
     * Decoy detection for "fake protection" re-packs.  A real 360 Jiagu ships a
     * real ELF/native `libjiagu*` artifact; planted decoys use a tiny text
     * placeholder and often carry an explicit Art-Jiagu "NeoArk" marker.
     * SignatureKiller re-packs embed the original app as `origin.apk` under
     * `assets/SignatureKiller/`.
     */
    private fun scanDecoys(zip: ZipFile, entries: List<String>): List<String> {
        val hits = mutableListOf<String>()
        for (e in entries) {
            val entry = zip.getEntry(e) ?: continue
            val size = entry.size
            if (e.substringAfterLast('/').contains("libjiagu", ignoreCase = true) && size in 1..2047) {
                hits.add("placeholder native: $e (${size} B, not a real ELF)")
            }
            if (size in 1..4095) {
                val head = zip.getInputStream(entry).use { it.readNBytes(512) }
                val latin = toLatin1(head)
                if (latin.contains("NeoArk", ignoreCase = true) ||
                    latin.contains("Art-Jiagu", ignoreCase = true) ||
                    latin.contains("fake 360", ignoreCase = true)
                ) {
                    hits.add("decoy marker content: $e")
                }
            }
        }
        entries.filter {
            val lower = it.lowercase()
            lower.contains("signaturekiller") && lower.contains("origin.apk")
        }.forEach { hits.add("embedded app: $it") }
        return hits
    }
}