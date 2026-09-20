package com.dpt.unpack

import com.dpt.unpack.code.CodeRecord
import com.dpt.unpack.code.OoooooOoooParser
import com.dpt.unpack.crack.KeyRecovery
import com.dpt.unpack.detection.DptDetector
import com.dpt.unpack.detection.ApkIdRunner
import com.dpt.unpack.detection.Profiler
import com.dpt.unpack.dex.DexParser
import com.dpt.unpack.lsp.ExternalTool
import com.dpt.unpack.lsp.LsparanoidDetector
import com.dpt.unpack.lsp.SmaliDeobfuscator
import com.dpt.unpack.restore.DexRestorer
import com.dpt.unpack.tools.RePairipTool
import com.dpt.unpack.validate.DexValidator
import com.dpt.unpack.ark.ArkDetector
import com.dpt.unpack.ark.ArkDumper
import com.dpt.unpack.ark.FridaDumper
import com.dpt.unpack.ark.ArkDexTools
import com.dpt.unpack.ark.ArkOatExtractor
import com.dpt.unpack.ark.ArkRebuilder
import com.dpt.unpack.checksum.DexChecksum
import com.dpt.unpack.b2al.B2AlDetector
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

data class CandidateScore(
    val idx: Int,
    val layoutDesc: String,
    val score: Double,
    val matched: Int,
    val total: Int,
)

// Mobile-friendly width
private const val UI_W = 42

/** Last-two-segments shorthand so phone screens don't wrap on absolute paths. */
private fun shortPath(f: File): String {
    val name = f.name
    val parent = f.parentFile?.name
    return if (parent.isNullOrBlank()) name else "$parent/$name"
}

// ANSI Colors for Clean UI
private const val ANSI_GREEN = "\u001B[32m"
private const val ANSI_BOLD_GREEN = "\u001B[1;32m"
private const val ANSI_RED = "\u001B[31m"
private const val ANSI_BOLD_YELLOW = "\u001B[1;33m"
private const val ANSI_RESET = "\u001B[0m"

private val utf8: Boolean = isUtf8Console() && System.getenv("NO_UTF8") == null

private fun isUtf8Console(): Boolean {
    val enc = System.getProperty("native.encoding")
        ?: System.getProperty("file.encoding")
        ?: "UTF-8"
    return enc.contains("UTF", ignoreCase = true) || enc.contains("utf-8", ignoreCase = true)
}

fun main(args: Array<String>) {
    var input: String? = null
    var output: String? = null
    var inspect = false
    var crack = true
    var debug = false
    var dumpManifest = false
    var aesKeyHex: String? = null
    var pkgOverride: String? = null
    var buildKeyOverride: String? = null
    var buildKeysFile: String? = null
    var mode: String? = null
    var deviceType: String? = null
    var rootMode: String? = null
    var adbPath: String? = null
    var timeoutSec: String? = null
    var dumpDir: String? = null
    var dumpMode: String? = null
    var fridaHost: String? = null
    var fridaPython: String? = null
    var appOverride: String? = null
    var noInstall = false
    var noLaunch = false
    var analyzeOnly = false
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "-i", "--input" -> input = args.getOrNull(++i)
            "-o", "--output" -> output = args.getOrNull(++i)
            "--mode" -> mode = args.getOrNull(++i)
            "--inspect" -> inspect = true
            "--crack" -> crack = true
            "--debug" -> debug = true
            "--dump-manifest" -> dumpManifest = true
            "--aes-key" -> aesKeyHex = args.getOrNull(++i)
            "--package" -> pkgOverride = args.getOrNull(++i)
            "--build-key" -> buildKeyOverride = args.getOrNull(++i)
            "--build-keys-file" -> buildKeysFile = args.getOrNull(++i)
            "--device" -> deviceType = args.getOrNull(++i)
            "--root" -> rootMode = args.getOrNull(++i)
            "--adb" -> adbPath = args.getOrNull(++i)
            "--timeout" -> timeoutSec = args.getOrNull(++i)
            "--dump-dir" -> dumpDir = args.getOrNull(++i)
            "--dump" -> dumpMode = args.getOrNull(++i)
            "--frida-host" -> fridaHost = args.getOrNull(++i)
            "--frida-python" -> fridaPython = args.getOrNull(++i)
            "--application" -> appOverride = args.getOrNull(++i)
            "--no-install" -> noInstall = true
            "--no-launch" -> noLaunch = true
            "--analyze" -> analyzeOnly = true
            "-h", "--help" -> {
                printUsage()
                return
            }
            else -> {
                if (input == null && !args[i].startsWith("-")) {
                    input = args[i]
                } else {
                    System.err.println("unknown option: ${args[i]}")
                    printUsage()
                    return
                }
            }
        }
        i++
    }
    if (input == null) {
        printUsage()
        return
    }

    val apk = File(input)
    if (!apk.isFile) {
        System.err.println("input apk not found: ${apk.absolutePath}")
        kotlin.system.exitProcess(1)
    }

    val outDir = output?.let(::File) ?: defaultOutDir(apk)

    if (analyzeOnly) {
        runAnalyzePipeline(apk)
        return
    }

    try {
        val chosen = resolveMode(apk, mode)
        val arkOpts = ArkOptions(
            deviceType = deviceType ?: "adb",
            rootMode = rootMode ?: "auto",
            adbPath = adbPath,
            timeoutSec = timeoutSec?.toIntOrNull() ?: 120,
            dumpDir = dumpDir,
            dumpMode = dumpMode,
            fridaHost = fridaHost,
            fridaPython = fridaPython,
            noInstall = noInstall,
            noLaunch = noLaunch,
            appOverride = appOverride,
            pkgOverride = pkgOverride,
        )
        when (chosen) {
            "dpt" -> runDptPipeline(apk, outDir, inspect, crack, debug, dumpManifest, aesKeyHex, pkgOverride, buildKeyOverride, buildKeysFile, ::hexToBytes)
            "lsparanoid" -> runLspPipeline(apk, outDir, debug)
            "ark" -> runArkPipeline(apk, outDir, debug, arkOpts)
            "b2al" -> runB2alPipeline(apk, outDir, debug, appOverride)
            "pairip" -> runPairip(apk, outDir, debug)
            "auto-all" -> runAutoAll(apk, outDir, debug, arkOpts)
            else -> throw IllegalStateException("unknown mode: $chosen")
        }
    } catch (e: Exception) {
        println()
        errorCard(e.message ?: "unknown error")
        if (debug) e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}

enum class DetectedPacker { DPT, LSPARANOID, ARK, B2AL, NONE, BOTH }

private fun detectPacker(apk: File): DetectedPacker {
    val dpt = runCatching { DptDetector.detect(apk).detected }.getOrDefault(false)
    val lsp = runCatching { LsparanoidDetector.isLsparanoid(apk) }.getOrDefault(false)
    val ark = runCatching { ArkDetector.detect(apk).detected }.getOrDefault(false)
    val b2al = runCatching { B2AlDetector.detect(apk).detected }.getOrDefault(false)
    return when {
        dpt && lsp -> DetectedPacker.BOTH
        b2al -> DetectedPacker.B2AL
        dpt -> DetectedPacker.DPT
        lsp -> DetectedPacker.LSPARANOID
        ark -> DetectedPacker.ARK
        else -> DetectedPacker.NONE
    }
}

/**
 * Decides which unpacker to run. Priority:
 *  1. explicit --mode
 *  2. interactive menu (when a console is attached)
 *  3. auto-detect
 */
private fun resolveMode(apk: File, mode: String?): String {
    val given = mode?.trim()?.lowercase()
    if (given != null) {
        return when (given) {
            "dpt", "shell", "1" -> "dpt"
            "lsp", "lsparanoid", "2" -> "lsparanoid"
            "ark", "360", "jiagu", "3" -> "ark"
            "pairip", "repairip", "4" -> "pairip"
            "b2al", "b2", "proxy", "6" -> "b2al"
            "auto-all", "oneshot", "full", "single", "5" -> "auto-all"
            "auto" -> autoPacker(apk)
            else -> throw IllegalStateException("unknown mode '$given' (use dpt | lsparanoid | ark | pairip | b2al | auto | auto-all)")
        }
    }
    val detected = detectPacker(apk)
    if (System.console() != null) {
        println()
        println(uiTop())
        println(uiRow("${ANSI_BOLD_GREEN}SELECT UNPACKER${ANSI_RESET}"))
        println(uiRow(""))
        println(uiRow("  1) DPT Shell      ${mark(detected == DetectedPacker.DPT || detected == DetectedPacker.BOTH)}"))
        println(uiRow("  2) LSParanoid     ${mark(detected == DetectedPacker.LSPARANOID || detected == DetectedPacker.BOTH)}"))
        println(uiRow("  3) 360 Jiagu (Ark)${mark(detected == DetectedPacker.ARK)}"))
        println(uiRow("  4) PairipProtect   (RePairip)"))
        println(uiRow("  5) AUTO all-in-one *"))
        println(uiRow("  6) B2Al Proxy Packer${mark(detected == DetectedPacker.B2AL)}"))
        println(uiRow(""))
        println(uiRow("detected: ${detectedLabel(detected)}"))
        println(uiBot())
        print("  choice [1/2/3]: ")
        System.out.flush()
        val line = readLine()?.trim()?.lowercase()
        return when (line) {
            "1", "dpt", "shell" -> "dpt"
            "2", "lsp", "lsparanoid" -> "lsparanoid"
            "3", "ark", "360", "jiagu" -> "ark"
            "4", "pairip", "repairip" -> "pairip"
            "5", "auto-all", "oneshot", "full", "single" -> "auto-all"
            "6", "b2al", "b2", "proxy" -> "b2al"
            "", null -> autoPacker(apk)
            else -> throw IllegalStateException("invalid choice '$line'")
        }
    }
    return autoPacker(apk)
}

private fun mark(active: Boolean) = if (active) "${ANSI_GREEN}*${ANSI_RESET}" else " "
private fun detectedLabel(d: DetectedPacker) = when (d) {
    DetectedPacker.DPT -> "DPT Shell"
    DetectedPacker.LSPARANOID -> "LSParanoid"
    DetectedPacker.ARK -> "360 Jiagu / ArkShell"
    DetectedPacker.B2AL -> "B2Al proxy packer"
    DetectedPacker.BOTH -> "DPT Shell + LSParanoid"
    DetectedPacker.NONE -> "none (unknown apk)"
}

private fun autoPacker(apk: File): String = when (detectPacker(apk)) {
    DetectedPacker.DPT -> "dpt"
    DetectedPacker.LSPARANOID -> "lsparanoid"
    DetectedPacker.ARK -> "ark"
    DetectedPacker.B2AL -> "b2al"
    DetectedPacker.BOTH -> throw IllegalStateException("apk has multiple protections (dpt/lsparanoid) - use --mode dpt|lsparanoid explicitly")
    DetectedPacker.NONE -> profileDispatch(apk)
}

/**
 * The classic detectors found nothing. Fall back to the broad static profiler:
 * if it identifies a protection stack we own a pipeline for, run that pipeline;
 * otherwise fail with a human-readable recommendation of the vendored tool.
 */
private fun profileDispatch(apk: File): String {
    val profile = Profiler.analyze(apk)
    if (profile.layers.isEmpty()) {
        throw IllegalStateException("no packer/protector fingerprint found - the apk looks raw (--analyze prints the full profile)")
    }
    val owned = Profiler.ownedStrategies() + if (RePairipTool.find() != null) "pairip" else ""
    val embedded = profile.layers.firstOrNull { it.strategy == "embedded" }
    if (embedded != null) {
        val src = embedded.evidence.firstOrNull { it.contains("origin.apk") }
            ?.substringAfter("embedded app: ") ?: "the embedded origin.apk"
        throw IllegalStateException(
            "apk is a re-pack: fake/low-effort 360 decoy with a real app embedded at '$src'. " +
                "Extract it first, then re-run --mode auto <extracted>."
        )
    }
    val ownedLayer = profile.layers.firstOrNull { it.strategy in owned }
    if (ownedLayer != null) return ownedLayer.strategy
    val top = profile.layers.first()
    throw IllegalStateException(
        "protection stack: ${profile.layers.joinToString(" + ") { it.name }}. " +
            "no built-in pipeline for '${top.strategy}' yet - " +
            if (top.tool != null) "vendor ${top.tool} (see tools/) then re-choose the backend." else "needs a custom backend."
    )
}

/**
 * One-shot fully automatic pipeline (--mode auto-all): profile the apk,
 * extract any embedded origin.apk (SignatureKiller re-pack) and recurse into
 * it, then pick the first built-in pipeline for the remaining protection stack
 * and run it.  Returns quietly when the apk is already raw.
 */
private fun runAutoAll(apk: File, outDir: File, debug: Boolean, opts: ArkOptions, depth: Int = 0) {
    banner()
    targetCard(apk)
    if (depth > 4) throw IllegalStateException("embedded chain too deep (>4) - refusing to recurse further")

    val profile = runWithSpinner(99, "Profiling APK", 99) { Profiler.analyze(apk) }

    val embedded = profile.layers.firstOrNull { it.strategy == "embedded" }
    if (embedded != null) {
        val hint = embedded.evidence.firstOrNull { it.contains("origin.apk") }
            ?.substringAfter("embedded app: ")
        val embeddedEntry = findEmbeddedApkEntry(apk, hint)
        if (embeddedEntry != null) {
            println()
            println(uiTop())
            println(uiRow("${ANSI_BOLD_YELLOW}EMBEDDED REPACK${ANSI_RESET}"))
            println(uiRow(" decoy shell:   ${embedded.name} (${"%.0f".format(embedded.likelihood * 100)}%)"))
            println(uiRow(" embedded app:  ${cut(embeddedEntry, 30)}"))
            println(uiBot())
            val innerDir = File(outDir, "embedded")
            innerDir.deleteRecursively(); innerDir.mkdirs()
            val origin = File(innerDir, "origin.apk")
            ZipFile(apk).use { z ->
                val entry = z.getEntry(embeddedEntry)
                    ?: throw IllegalStateException("embedded entry vanished during read: $embeddedEntry")
                z.getInputStream(entry).use { i -> origin.outputStream().use { o -> i.copyTo(o) } }
            }
            println("   extracted ${fmtSize(origin.length())} -> ${shortPath(origin)}")
            println("   -> recursing into the embedded origin.apk")
            runAutoAll(origin, innerDir, debug, opts, depth + 1)
            return
        }
        println()
        println(uiTop())
        println(uiRow("${ANSI_BOLD_YELLOW}DECOY-ONLY SIGNATURE${ANSI_RESET}"))
        println(uiRow(" ${embedded.name} without any embedded apk"))
        if (!hasRealArkShell(apk)) {
            staticFakeShell(apk, outDir)
            return
        }
        println(uiRow(" -> falling through to owned-pipeline routes"))
        println(uiBot())
    }

    if (profile.layers.isEmpty()) {
        println()
        println(uiTop())
        println(uiRow("${ANSI_GREEN}APK IS RAW - nothing to unpack${ANSI_RESET}"))
        println(uiBot())
        return
    }

    val owned = Profiler.ownedStrategies() + if (RePairipTool.find() != null) "pairip" else ""
    val layer = profile.layers.firstOrNull { it.strategy in owned }
        ?: fallbackClassic(apk).let { classic ->
            if (classic != null) return when (classic) {
                "dpt" -> runDptPipeline(
                    apk, outDir, inspect = false, crack = true, debug = debug, dumpManifest = false,
                    aesKeyHex = null, pkgOverride = opts.pkgOverride,
                    buildKeyOverride = null, buildKeysFile = null, hexToBytes = ::hexToBytes
                )
                "lsparanoid" -> runLspPipeline(apk, outDir, debug)
                "ark" -> {
                    if (fakeArkRoute(apk, outDir)) return
                    runArkPipeline(apk, outDir, debug, opts)
                }
                "b2al" -> runB2alPipeline(apk, outDir, debug, opts.appOverride)
                else -> throw IllegalStateException("classic fallback produced '${classic}'")
            }
            profile.layers.first().let { top ->
                throw IllegalStateException(
                    "protection stack: ${profile.layers.joinToString(" + ") { it.name }}. " +
                        "no built-in pipeline for '${top.strategy}' - " +
                        (top.tool?.let { "vendor $it (see tools/)" } ?: "needs a custom backend")
                )
            }
        }
    println()
    println(uiTop())
    println(uiRow("${ANSI_BOLD_GREEN}AUTO ROUTE${ANSI_RESET}"))
    println(uiRow(" strategy: ${strategyLabel(layer.strategy)}"))
    println(uiRow(" stack:    ${profile.layers.joinToString(" + ") { it.name }}"))
    println(uiBot())

    when (layer.strategy) {
        "dpt" -> runDptPipeline(
            apk, outDir, inspect = false, crack = true, debug = debug, dumpManifest = false,
            aesKeyHex = null, pkgOverride = opts.pkgOverride,
            buildKeyOverride = null, buildKeysFile = null, hexToBytes = ::hexToBytes
        )
        "lsparanoid" -> runLspPipeline(apk, outDir, debug)
        "ark" -> {
            if (fakeArkRoute(apk, outDir)) return
            runArkPipeline(apk, outDir, debug, opts)
        }
        "b2al" -> runB2alPipeline(apk, outDir, debug, opts.appOverride)
        "pairip" -> runPairip(apk, outDir, debug)
        else -> throw IllegalStateException("unsupported auto strategy: ${layer.strategy}")
    }
}

/** Locate the embedded origin.apk inside a repacked shell apk (hint first, then scan). */
private fun findEmbeddedApkEntry(apk: File, hint: String?): String? {
    ZipFile(apk).use { z ->
        val names = z.entries().asSequence().map { it.name }.toList()
        if (hint != null && names.contains(hint)) return hint
        names.firstOrNull { it.endsWith("origin.apk") }?.let { return it }
        return names.firstOrNull { it.startsWith("assets/") && it.endsWith(".apk") }
    }
}

/**
 * A marker-only fake shell (no real libjiagu.so, no embedded origin.apk) has no
 * runtime payload to decrypt - deliver the clean readable copy and stop.
 */
private fun staticFakeShell(apk: File, outDir: File) {
    println()
    println(uiTop())
    println(uiRow("${ANSI_BOLD_YELLOW}DECOY-ONLY SIGNATURE${ANSI_RESET}"))
    println(uiRow(" ${ANSI_GREEN}FAKE SHELL ONLY${ANSI_RESET} - no real 360 native shell,"))
    println(uiRow(" no embedded payload -> no runtime encryption to undo statically"))
    println(uiBot())
    val finalCopy = File(outDir, apk.name.removeSuffix(".apk") + "-unpacked.apk")
    apk.copyTo(finalCopy, overwrite = true)
    println("   clean copy delivered: ${finalCopy.absolutePath}")
}

/** True when a layer route is ark but the apk has no real jiagu shell - treat as static fake. */
private fun fakeArkRoute(apk: File, outDir: File): Boolean {
    if (hasRealArkShell(apk)) return false
    staticFakeShell(apk, outDir)
    return true
}

/**
 * True when the apk ships a real 360 Jiagu native shell (lib/<abi>/libjiagu.so).
 * A "fake 360" decoy only carries a tiny placeholder (assets/libjiagu_mips.a)
 * and its own libs, so it is statically readable and must not go to the device
 * route.
 */
private fun hasRealArkShell(apk: File): Boolean {
    ZipFile(apk).use { z ->
        return z.entries().asSequence().map { it.name }.any {
            it.startsWith("lib/") && it.contains("jiagu", ignoreCase = true) && it.endsWith(".so")
        }
    }
}

/** Classic quick detectors (DptDetector / LsparanoidDetector / ArkDetector) as a last resort. */
private fun fallbackClassic(apk: File): String? {
    val dpt = runCatching { DptDetector.detect(apk).detected }.getOrDefault(false)
    val lsp = runCatching { LsparanoidDetector.isLsparanoid(apk) }.getOrDefault(false)
    val ark = runCatching { ArkDetector.detect(apk).detected }.getOrDefault(false)
    val b2al = runCatching { B2AlDetector.detect(apk).detected }.getOrDefault(false)
    return when {
        dpt -> "dpt"
        lsp -> "lsparanoid"
        b2al -> "b2al"
        ark -> "ark"
        else -> null
    }
}

private fun defaultOutDir(apk: File): File {
    val base = apk.name.removeSuffix(".apk")
    val parent = apk.absoluteFile.parentFile ?: File(".")
    return File(parent, "$base-unpacked")
}

/**
 * Keep the output directory tidy: remove every intermediate generated while
 * producing the final APK (unsigned/aligned builds, .idsig sidecars, the
 * throw-away keystore, patched_dex/, and the decoded smali tree), leaving only
 * the final `-unpacked.apk`. Also removes the `<base>-rebuilt.apk` staged next
 * to the output dir by the LSParanoid pipeline. Returns the number of items
 * removed.
 */
private fun tidyOutdir(outDir: File, keep: Set<String>): Int {
    var removed = 0
    outDir.listFiles()?.forEach { f ->
        if (f.name in keep) return@forEach
        val ok = if (f.isDirectory) runCatching { f.deleteRecursively() }.getOrDefault(false) else f.delete()
        if (ok) removed++
    }
    val leftover = keep.firstOrNull()?.removeSuffix("-unpacked.apk")?.plus("-rebuilt.apk")
    if (leftover != null) {
        val staged = File(outDir.parentFile ?: outDir, leftover)
        if (staged.isFile && staged.delete()) removed++
    }
    return removed
}

/** RePairip (PairipProtect deprotection) pipeline: process APK/APKS, then optional translation patch. */
private fun runPairip(apk: File, outDir: File, debug: Boolean): String {
    val ref = RePairipTool.find()
        ?: throw IllegalStateException("RePairip.jar not found - set DPT_REPAIRIP_JAR or drop it into tools/")
    banner()
    println()
    println(uiTop())
    println(uiRow("${ANSI_BOLD_GREEN}P A I R I P   D E P R O T E C T${ANSI_RESET}"))
    println(uiRow("tool:    ${ref.jar.name}"))
    println(uiRow("input:   ${cut(apk.name, 30)}"))
    println(uiBot())
    println()
    println("   [1/3] ${ANSI_GREEN}RePairip: merge/load APK bundle${ANSI_RESET}")
    val json = File(outDir, "pairip.json").takeIf { it.isFile }
        ?: apk.absoluteFile.parentFile?.let { p -> File(p, apk.name.removeSuffix(".apk") + "-pairip.json") }
            ?.takeIf { it.isFile }
    if (json != null) println("   [2/3] ${ANSI_GREEN}RePairip: translation patch with ${json.name}${ANSI_RESET}")
    val out = RePairipTool.run(ref, apk, json, lazymod = false)
    println(out.lineSequence().filter { it.isNotBlank() }.toList().takeLast(20).joinToString("\n"))
    println("   [3/3] ${ANSI_GREEN}output written next to input${ANSI_RESET}")
    return out
}

private fun hexToBytes(hex: String): ByteArray? {
    val clean = hex.trim().replace(" ", "")
    if (clean.isEmpty() || clean.length % 2 != 0) return null
    return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

private fun printUsage() {
    println("${ANSI_BOLD_GREEN}UNPACKER BY FAHAD${ANSI_RESET}")
    println(" github: https://github.com/0xgf18")
    println(" usage: fahad-unpacker <input.apk> [options]")
    println("")
    println(" options:")
    println("   -i, --input <apk>       input apk (or first positional arg)")
    println("   -o, --output <dir>      output directory")
    println("   --mode <dpt|lsparanoid|ark|pairip|b2al|auto|auto-all>")
    println("                           dpt: DPT Shell payload restore")
    println("                           lsparanoid: LSParanoid string deobfuscation")
    println("                           ark: 360 Jiagu / ArkShell runtime dump + rebuild")
    println("                           b2al: B2Al proxy packer chain recover + rebuild")
    println("                           pairip: PairipProtect deprotection (RePairip)")
    println("                           auto: detect automatically (default: interactive)")
    println("                           auto-all: one-shot pipeline - extract embedded")
    println("                                     apk if present, then auto-pick & run")
    println("                                     (run.sh defaults to this)")
    println("       (--mode 1/2/3/4/5/6 in the menu also works)")
    println("   --inspect               print layout info only (dpt)")
    println("   --crack                 attempt DPT payload key recovery (default)")
    println("   --debug                 verbose output")
    println("   --dump-manifest         dump manifest")
    println("   --aes-key <hex>         override DPT AES key")
    println("   --package <pkg>         override target package (dpt + ark)")
    println("   --build-key <key>       override build key")
    println("   --build-keys-file <f>   load build keys from file")
    println("   -h, --help              this help")
    println("")
    println(" ark/360 options:")
    println("   --device <adb|local>    adb = host drives device (default); local = on-device Termux")
    println("   --root <auto|su|shizuku|bluestacks>")
    println("                           auto (default): local uses rish if installed else su;")
    println("                           adb maps to su. shizuku runs commands via rish (no root,")
    println("                           works for --device local). bluestacks is adb-only.")
    println("   --adb <path>            path to adb binary (default: PATH / \$ANDROID_HOME)")
    println("   --timeout <sec>         max seconds to wait for payload decrypt (default 120)")
    println("   --dump <disk|frida|auto>payload collection strategy (default disk)")
    println("                           disk: poll code_cache for ark_payload_*.dex")
    println("                           frida: deep-scan the live process with frida-dexdump")
    println("                                 (for in-memory loaders that never write to disk)")
    println("                           auto: try disk first, fall back to frida")
    println("   --dump-dir <dir>        skip device: read already-dumped payloads from dir")
    println("                           (accepts ark_payload_*.dex or frida-dexdump classes*.dex)")
    println("   --frida-host <host:prt> frida-server endpoint (default 127.0.0.1:27042)")
    println("   --frida-python <cmd>    python with the frida_dexdump module (default: auto)")
    println("                           (also honored: \$DPT_PYTHON)")
    println("   --application <class>   force real Application class for the manifest")
    println("   --no-install            do not (re)install the apk on the device")
    println("   --no-launch             do not start the app (for use with --dump-dir)")
    println("   --analyze               analyze only: detect packer/obfuscator/protector")
    println("                           and print the recommended unpacker (no dump)")
    println("")
    println(" environment:")
    println("   DPT_APKTOOL_JAR         path to apktool.jar (LSParanoid mode)")
    println("   APKTOOL_HOME            directory holding apktool.jar")
    println("   DPT_BUILD_TOOLS         Android build-tools dir (signing)")
    println("   ANDROID_HOME            fallback for build-tools / adb")
}

private fun runDptPipeline(
    apk: File, outDir: File, inspect: Boolean, crack: Boolean, debug: Boolean,
    dumpManifest: Boolean, aesKeyHex: String?, pkgOverride: String?,
    buildKeyOverride: String?, buildKeysFile: String?, hexToBytes: (String) -> ByteArray?
) {
    val start = System.currentTimeMillis()
    banner()

    if (dumpManifest) {
        // Omitting manifest dump log for brevity if triggered
        return
    }

    targetCard(apk)

    // Stage 1
    val t1 = System.currentTimeMillis()
    val detection = runWithSpinner(1, "Detecting Payload") {
        DptDetector.detect(apk)
    }
    if (!detection.detected) throw IllegalStateException("not a DPT-packed apk")
    val payloadDexes = detection.payloadDexes
    val codeAsset = detection.codeAsset!!
    val candidates = OoooooOoooParser.parseCandidates(codeAsset)
    if (candidates.isEmpty()) throw IllegalStateException("unknown layout")
    
    val capacitiesByDex = payloadDexes.map { dex -> DexParser.parseMethods(dex.bytes).associate { it.methodIdx to it.insnsByteSize } }
    val bestScore = pickBestCandidate(candidates, payloadDexes, capacitiesByDex)
    val best = candidates[bestScore.idx]
    stageDone(System.currentTimeMillis() - t1)

    // Stage 2
    val t2 = System.currentTimeMillis()
    val resolved = runWithSpinner(2, "Recovering Key") {
        determineAesKey(apk, aesKeyHex, crack, debug, pkgOverride, buildKeyOverride, buildKeysFile, hexToBytes)
    }
    val probeRecords = best.sections.values.firstOrNull { it.isNotEmpty() } ?: emptyList()
    val plaintextRate = if (probeRecords.isNotEmpty()) KeyRecovery.verifyPlaintextPrologueStats(probeRecords) else 0.0
    val hasConfig = java.util.zip.ZipFile(apk).use { z -> z.getEntry("assets/d_shell_data_001") != null }
    val plaintextStore = !hasConfig || plaintextRate >= 0.6

    val keyBin: ByteArray? = if (plaintextStore) null else hexToBytes(resolved.key?.aesKeyHex ?: aesKeyHex ?: throw java.lang.IllegalStateException("key recovery failed"))
    stageDone(System.currentTimeMillis() - t2)

    // Stage 3
    val t3 = System.currentTimeMillis()
    stageHead(3, "Restoring Dex Bodies")
    val patchedDir = File(outDir, "patched_dex")
    patchedDir.deleteRecursively(); patchedDir.mkdirs()
    var totalRestored = 0
    for (dexIndex in best.sections.keys.sorted()) {
        val records = best.sections[dexIndex]!!
        val dex = payloadDexes.getOrNull(dexIndex) ?: continue
        val dexLabel = if (dexIndex == 0) "classes.dex" else "classes${dexIndex + 1}.dex"
        val result = DexRestorer.restore(dex.bytes, records, keyBin, label = dexLabel)
        totalRestored += result.patched
        if (result.dex.size > 50000) {
            val p = result.dex
            val sb = StringBuilder()
            for (i in 0 until 32) { sb.append(java.lang.String.format("%02X", p[40248 + 16 + 4 + i].toInt() and 0xFF)); if (i % 2 == 1) sb.append(' ') }
            println("   WRITE cls${dexIndex} clinit@40248: $sb in=${p.size}B")
        }
        result.dex.writeTo(File(patchedDir, result.nameFor(dexIndex)))
        val bar = progressBar(if (result.totalRecords > 0) 1.0 else 0.0)
        println("   ${result.nameFor(dexIndex).padEnd(14)} [${result.patched}] [$bar] OK  hooks=${result.hooksNeutralized} bridges=${result.bridgesNeutralized}")
    }
    stageDone(System.currentTimeMillis() - t3)

    // Stage 4
    val t4 = System.currentTimeMillis()
    runWithSpinner(4, "Rebuilding APK") {
        val manifestBytes = java.util.zip.ZipFile(apk).use { z -> z.getEntry("AndroidManifest.xml")?.let { z.getInputStream(it).readBytes() } } ?: error("no manifest")
        val restoredDir = File(outDir, "patched_dex")
        val dexFiles: List<File> = restoredDir.listFiles { f, n -> n.startsWith("classes") && n.endsWith(".dex") }
            ?.sortedBy { f ->
                if (f.name == "classes.dex") 0 else f.name.removePrefix("classes").removeSuffix(".dex").toInt()
            } ?: emptyList()
        val payloadDexes = dexFiles.map { it.readBytes() } ?: emptyList()
        // mirror the Ark pipeline: point the manifest back at the real Application
        // instead of leaving the attribute removed (apps with a custom Application
        // child class crash / misbehave when the default getApplication() is used).
        val realApp = ArkDexTools.discoverRealApplication(null, payloadDexes, null)
        // Point <application android:name> at the real Application.  The original
        // (packed) manifest already carries a `name` attribute holding the shell's
        // ProxyApplication, so setApplicationName overwrites that value in place;
        // no attribute add/remove structural change is required.  The shell's
        // appComponentFactory (ProxyComponentFactory) class no longer exists in
        // the restored dexes, so it must be removed or the framework throws
        // ClassNotFoundException > ProxyComponentFactory during super.onCreate.
        var rootManifest = if (realApp != null) {
            com.dpt.unpack.axml.AxmlManifest.setApplicationName(manifestBytes, realApp)
        } else {
            com.dpt.unpack.axml.AxmlManifest.restoreApplication(manifestBytes)
        }
        rootManifest = com.dpt.unpack.axml.AxmlManifest.removeAttribute(
            rootManifest, "application", "appComponentFactory"
        )
        if (realApp != null) println("\n   application-name = $realApp".replace('/', '.'))
        val unsigned = File(outDir, "unsigned.apk")
        com.dpt.unpack.rebuild.ApkRebuilder.rebuild(apk, patchedDir, rootManifest, unsigned)
        val finalName = apk.name.removeSuffix(".apk") + "-unpacked.apk"
        signAndDeliver(unsigned, finalName, outDir)
    }
    stageDone(System.currentTimeMillis() - t4)

    // Stage 5
    val t5 = System.currentTimeMillis()
    val finalName = apk.name.removeSuffix(".apk") + "-unpacked.apk"
    val finalApk = File(outDir, finalName)
    val sha = sha256(finalApk.readBytes())
    stageDone(System.currentTimeMillis() - t5)

    val removed = tidyOutdir(outDir, setOf(finalName))
    if (removed > 0) println("   ${ANSI_GREEN}✓ cleaned $removed intermediate files${ANSI_RESET}")
    resultCard(finalName, outDir, sha, finalApk.length(), System.currentTimeMillis() - start)
}

/**
 * Best-effort signing: sign+align when a signer exists, otherwise or on any
 * signer failure deliver the rebuilt apk as-is (unsigned). Termux without the
 * apksigner package or a misbehaving signer must never block delivery.
 */
private fun signAndDeliver(rebuilt: File, finalName: String, outDir: File) {
    val finalApk = File(outDir, finalName)
    if (finalApk.exists()) finalApk.delete()
    try {
        val buildTools = com.dpt.unpack.rebuild.Signer.findBuildTools()
        val aligned = File(outDir, "aligned.apk")
        if (buildTools != null) {
            com.dpt.unpack.rebuild.Signer.align(buildTools, rebuilt, aligned)
            com.dpt.unpack.rebuild.Signer.sign(buildTools, com.dpt.unpack.rebuild.Signer.ensureKeystore(outDir), aligned)
            aligned.renameTo(finalApk)
        } else {
            val signer = com.dpt.unpack.rebuild.Signer.findPathBinary("apksigner")
            if (signer != null) {
                com.dpt.unpack.rebuild.Signer.alignWithPathBinary(
                    com.dpt.unpack.rebuild.Signer.findPathBinary("zipalign"), rebuilt, aligned
                )
                com.dpt.unpack.rebuild.Signer.signWithPathBinary(signer, com.dpt.unpack.rebuild.Signer.ensureKeystore(outDir), aligned)
                aligned.renameTo(finalApk)
            } else {
                rebuilt.copyTo(finalApk, overwrite = true)
                println("\n   (no apksigner found - output is UNSIGNED)")
            }
        }
    } catch (e: Exception) {
        rebuilt.copyTo(finalApk, overwrite = true)
        println("\n   (signing skipped: ${e.message?.lineSequence()?.firstOrNull()}) - output is UNSIGNED")
    }
}

// ---------------------------------------------------------------------------
// LSParanoid pipeline (string deobfuscation)
// ---------------------------------------------------------------------------

private fun runLspPipeline(
    apk: File, outDir: File, debug: Boolean
) {
    val start = System.currentTimeMillis()
    banner()
    targetCard(apk)

    // Stage 1 - confirm LSParanoid
    val t1 = System.currentTimeMillis()
    runWithSpinner(1, "Detecting LSParanoid", 6) {
        if (!LsparanoidDetector.isLsparanoid(apk)) throw IllegalStateException("no LSParanoid runtime in apk")
    }
    stageDone(System.currentTimeMillis() - t1)

    // Stage 2 - locate apktool
    val t2 = System.currentTimeMillis()
    val apktool = runWithSpinner(2, "Locating apktool", 6) {
        ExternalTool.findApktool() ?: throw IllegalStateException("apktool not found (set DPT_APKTOOL_JAR or put apktool.jar next to the tool)")
    }
    stageDone(System.currentTimeMillis() - t2)

    // Stage 3 - decode to smali
    // If we are unpacking an APK that lives INSIDE the output dir (recursive
    // embedded repack: outDir/embedded/origin.apk), never wipe outDir - that
    // would delete the input itself. Decode into a separate .work dir instead.
    val apkInOut = apk.absoluteFile.absolutePath.startsWith(outDir.absoluteFile.absolutePath + File.separator)
    val work = if (apkInOut) File(outDir, ".work") else outDir
    if (work.isDirectory) work.deleteRecursively()
    work.mkdirs()
    val t3 = System.currentTimeMillis()
    runWithSpinner(3, "Decompiling to smali (apktool d)", 6) {
        ExternalTool.runApktool(apktool, "d", apk.absolutePath, "-o", work.absolutePath, "-f")
    }
    stageDone(System.currentTimeMillis() - t3)

    // Stage 4 - resolve getString calls + cleanup
    val t4 = System.currentTimeMillis()
    val summary = runQuiet(4, "Resolving getString calls", 6) {
        SmaliDeobfuscator.run(work, cleanup = true)
    }
    println()
    println("   rounds:   ${summary.rounds}")
    println("   calls:    ${summary.resolved}/${summary.total} resolved (${summary.skipped} skipped, ${summary.errors} errors)")
    for (line in summary.arrays) println("   array:    $line")
    stageDone(System.currentTimeMillis() - t4)

    // Stage 5 - rebuild
    val rebuilt = File(outDir.parentFile ?: File("."), apk.name.removeSuffix(".apk") + "-rebuilt.apk")
    rebuilt.delete()
    val t5 = System.currentTimeMillis()
    runWithSpinner(5, "Rebuilding apk (apktool b)", 6) {
        ExternalTool.runApktool(apktool, "b", work.absolutePath, "-o", rebuilt.absolutePath)
    }
    stageDone(System.currentTimeMillis() - t5)

    // Stage 6 - sign (best-effort)
    val t6 = System.currentTimeMillis()
    runWithSpinner(6, "Signing", 6) {
        signAndDeliver(rebuilt, apk.name.removeSuffix(".apk") + "-unpacked.apk", outDir)
    }
    stageDone(System.currentTimeMillis() - t6)

    val finalName = apk.name.removeSuffix(".apk") + "-unpacked.apk"
    val finalApk = File(outDir, finalName)
    if (!finalApk.isFile) throw IllegalStateException("output apk missing: ${finalApk.path}")
    val sha = sha256(finalApk.readBytes())
    val removed = tidyOutdir(outDir, setOf(finalName))
    if (removed > 0) println("   ${ANSI_GREEN}✓ cleaned $removed intermediate files${ANSI_RESET}")
    resultCard(finalName, outDir, sha, finalApk.length(), System.currentTimeMillis() - start)
}

// ---------------------------------------------------------------------------
// ArkShell / 360 Jiagu pipeline (runtime dump + rebuild)
// ---------------------------------------------------------------------------

private data class ArkOptions(
    val deviceType: String,
    val rootMode: String,
    val adbPath: String?,
    val timeoutSec: Int,
    val dumpDir: String?,
    val dumpMode: String?,
    val fridaHost: String?,
    val fridaPython: String?,
    val noInstall: Boolean,
    val noLaunch: Boolean,
    val appOverride: String?,
    val pkgOverride: String?,
)

private fun runArkPipeline(apk: File, outDir: File, debug: Boolean, opts: ArkOptions) {
    val start = System.currentTimeMillis()
    banner()
    targetCard(apk)

    // Stage 1 - detect
    val t1 = System.currentTimeMillis()
    val info = runWithSpinner(1, "Detecting 360 Jiagu / ArkShell") {
        val r = ArkDetector.detect(apk)
        if (!r.detected) throw IllegalStateException("apk does not look like a 360-Jiagu pack (no b2al / libjiagu fingerprint)")
        r
    }
    info.reasons.forEach { println("   $it") }
    stageDone(System.currentTimeMillis() - t1)

    val pkg = opts.pkgOverride ?: info.packageName
        ?: throw IllegalStateException("could not read package name from manifest (use --package)")

    // Stage 2 - collect payload containers (device dump, frida in-memory dump or local --dump-dir)
    val t2 = System.currentTimeMillis()
    val dumpMode = opts.dumpMode ?: "disk"
    val rawPayloads = if (opts.dumpDir != null) {
        runWithSpinner(2, "Reading dumped payloads from ${opts.dumpDir}") {
            val dir = File(opts.dumpDir)
            dir.listFiles { f, name -> (name.startsWith("ark_payload") || name.startsWith("classes")) && name.endsWith(".dex") }
                ?.sortedBy { f ->
                    val m = Regex("(\\d+)").find(f.name.substringAfterLast("_"))
                    if (f.name == "classes.dex") 0 else m?.groupValues?.get(1)?.toIntOrNull() ?: 0
                }?.map { com.dpt.unpack.ark.DumpPayload(it.name, it.readBytes()) }
                ?.ifEmpty { throw IllegalStateException("no ark_payload_*.dex/classes*.dex files in ${opts.dumpDir}") }
                ?: throw IllegalStateException("cannot read ${opts.dumpDir}")
        }
    } else {
        runWithSpinner(2, "Dumping payloads (${info.packageName ?: pkg}) via ${opts.deviceType}" + if (dumpMode == "frida") " + frida" else "") {
            val device = ArkDumper.device(opts.deviceType, opts.rootMode, opts.adbPath)
            println("\n   device: ${device.hint()}   package: $pkg")
            if (!opts.noInstall) {
                val r = device.installApk(apk)
                if (r.exit != 0) println("   install: exit ${r.exit} (note: ${r.text.trim()})")
            }
            if (!opts.noLaunch) {
                val act = info.launcherActivity
                val launch: String = if (act != null) "am start -n $pkg/${act}" else "monkey -p $pkg 1"
                device.root("$launch 2>/dev/null; true")
                println("   launched: $launch  (waiting up to ${opts.timeoutSec}s for decryption...)")
            }
            if (dumpMode == "frida") {
                println("   -> frida in-memory dump (deep scan of the live process)")
                FridaDumper.dumpInMemory(
                    device, opts.deviceType, opts.adbPath, pkg,
                    timeoutSec = opts.timeoutSec, host = opts.fridaHost ?: "127.0.0.1:27042",
                    python = opts.fridaPython,
                )
            } else {
                try {
                    ArkDumper.pullPayloads(device, pkg, opts.timeoutSec * 1000L)
                } catch (e: IllegalStateException) {
                    // in-memory loaders never produce ark_payload_*.dex on disk ->
                    // fall back to a live frida scan when the user allows it
                    if (dumpMode == "auto") {
                        println("   ${e.message?.lineSequence()?.firstOrNull()}")
                        println("   -> falling back to frida in-memory dump (deep scan)")
                        FridaDumper.dumpInMemory(
                            device, opts.deviceType, opts.adbPath, pkg,
                            timeoutSec = opts.timeoutSec, host = opts.fridaHost ?: "127.0.0.1:27042",
                            python = opts.fridaPython,
                        )
                    } else {
                        throw e
                    }
                }
            }
        }
    }
    println("   payload containers: ${rawPayloads.size} (${fmtSize(rawPayloads.sumOf { it.bytes.size.toLong() })})")
    stageDone(System.currentTimeMillis() - t2)

    // Stage 3 - extract embedded dexes + fix checksums
    val t3 = System.currentTimeMillis()
    runWithSpinner(3, "Extracting dexes from OAT containers") {
        val patchedDir = File(outDir, "patched_dex")
        patchedDir.deleteRecursively(); patchedDir.mkdirs()
        rawPayloads.forEachIndexed { idx, p ->
            val dex = ArkOatExtractor.extract(p.bytes, p.name)
            val fixed = DexChecksum.fix(dex)
            val problems = DexValidator.validate(fixed)
            if (problems.isNotEmpty()) {
                if (debug) println("   ${p.name}: ${problems.joinToString("; ")}")
            }
            val outName = if (idx == 0) "classes.dex" else "classes${idx + 1}.dex"
            File(patchedDir, outName).writeBytes(fixed)
        }
    }
    stageDone(System.currentTimeMillis() - t3)

    // Stage 4 - real Application + manifest
    val t4 = System.currentTimeMillis()
    val realApp = runWithSpinner(4, "Restoring Application entry point") {
        val manifestBytes = info.manifest ?: throw IllegalStateException("no manifest in apk")
        val stub = info.stubDex
        val payloadDexes = File(outDir, "patched_dex").listFiles { f, n -> n.startsWith("classes") && n.endsWith(".dex") }
            ?.sortedBy { f ->
                if (f.name == "classes.dex") 0 else f.name.removePrefix("classes").removeSuffix(".dex").toInt()
            }?.map { it.readBytes() } ?: emptyList()
        val real = ArkDexTools.discoverRealApplication(stub, payloadDexes, opts.appOverride)
        if (real != null) {
            println("\n   application: $real")
            manifestBytes to real
        } else {
            // no custom Application subclass exists -> the stub hook is the only
            // marker; dropping it lets the framework use the default Application.
            println("\n   application: (none - default Application; stub marker stripped)")
            manifestBytes to null
        }
    }
    stageDone(System.currentTimeMillis() - t4)

    // Stage 5 - rebuild + sign
    val t5 = System.currentTimeMillis()
    runWithSpinner(5, "Rebuilding APK") {
        val (manifestBytes, realApp) = realApp
        val patchedManifest = if (realApp != null) {
            com.dpt.unpack.axml.AxmlManifest.setApplicationName(manifestBytes, realApp)
        } else {
            com.dpt.unpack.axml.AxmlManifest.restoreApplication(manifestBytes)
        }
        val unsigned = File(outDir, "unsigned.apk")
        ArkRebuilder.rebuild(apk, File(outDir, "patched_dex"), patchedManifest, unsigned)
        signAndDeliver(unsigned, apk.name.removeSuffix(".apk") + "-unpacked.apk", outDir)
    }
    stageDone(System.currentTimeMillis() - t5)

    val finalName = apk.name.removeSuffix(".apk") + "-unpacked.apk"
    val finalApk = File(outDir, finalName)
    if (!finalApk.isFile) throw IllegalStateException("output apk missing: ${finalApk.path}")
    val sha = sha256(finalApk.readBytes())
    val removed = tidyOutdir(outDir, setOf(finalName))
    if (removed > 0) println("   ${ANSI_GREEN}✓ cleaned $removed intermediate files${ANSI_RESET}")
    resultCard(finalName, outDir, sha, finalApk.length(), System.currentTimeMillis() - start)
}

// ---------------------------------------------------------------------------
// B2Al proxy packer pipeline (static chain recover + rebuild)
// ---------------------------------------------------------------------------

private fun runB2alPipeline(apk: File, outDir: File, debug: Boolean, appOverride: String?) {
    val start = System.currentTimeMillis()
    banner()
    targetCard(apk)

    // Stage 1 - detect + recover the record chain
    val t1 = System.currentTimeMillis()
    val info = runWithSpinner(1, "Detecting B2Al proxy carrier") {
        val r = B2AlDetector.detect(apk)
        if (!r.detected) throw IllegalStateException("apk is not a B2Al proxy packer (${r.reasons.lastOrNull() ?: "no carrier chain"})")
        r
    }
    info.reasons.forEach { println("   $it") }
    stageDone(System.currentTimeMillis() - t1)

    // Stage 2 - write recovered dexes
    val t2 = System.currentTimeMillis()
    runWithSpinner(2, "Recovering ${info.records.size} dex records") {
        val patchedDir = File(outDir, "patched_dex")
        patchedDir.deleteRecursively(); patchedDir.mkdirs()
        for (rec in info.records) {
            val name = if (rec.index == 1) "classes.dex" else "classes${rec.index}.dex"
            File(patchedDir, name).writeBytes(rec.data)
        }
    }
    stageDone(System.currentTimeMillis() - t2)

    // Stage 3 - real Application + manifest
    val t3 = System.currentTimeMillis()
    val realApp = runWithSpinner(3, "Restoring Application entry point") {
        val manifestBytes = java.util.zip.ZipFile(apk).use { z -> z.getEntry("AndroidManifest.xml")?.let { z.getInputStream(it).readBytes() } }
            ?: throw IllegalStateException("no AndroidManifest.xml in apk")
        val payloadDexes = File(outDir, "patched_dex").listFiles { f, n -> n.startsWith("classes") && n.endsWith(".dex") }
            ?.sortedBy { f ->
                if (f.name == "classes.dex") 0 else f.name.removePrefix("classes").removeSuffix(".dex").toInt()
            }?.map { it.readBytes() } ?: emptyList()
        val real = appOverride
            ?: info.applicationClass
            ?: ArkDexTools.discoverRealApplication(null, payloadDexes, null)
            ?: throw IllegalStateException("could not find the real Application class in the recovered dexes - pass --application <com.x.RealApp>")
        println("\n   application: $real")
        manifestBytes to real
    }
    stageDone(System.currentTimeMillis() - t3)

    // Stage 4 - rebuild + sign
    val t4 = System.currentTimeMillis()
    runWithSpinner(4, "Rebuilding APK") {
        val (manifestBytes, realApp) = realApp
        val patchedManifest = com.dpt.unpack.axml.AxmlManifest.setApplicationName(manifestBytes, realApp.replace('/', '.'))
        val unsigned = File(outDir, "unsigned.apk")
        ArkRebuilder.rebuild(apk, File(outDir, "patched_dex"), patchedManifest, unsigned)
        signAndDeliver(unsigned, apk.name.removeSuffix(".apk") + "-unpacked.apk", outDir)
    }
    stageDone(System.currentTimeMillis() - t4)

    // Stage 5 - finalize
    val t5 = System.currentTimeMillis()
    val finalName = apk.name.removeSuffix(".apk") + "-unpacked.apk"
    val finalApk = File(outDir, finalName)
    if (!finalApk.isFile) throw IllegalStateException("output apk missing: ${finalApk.path}")
    val sha = sha256(finalApk.readBytes())
    stageDone(System.currentTimeMillis() - t5)

    val removed = tidyOutdir(outDir, setOf(finalName))
    if (removed > 0) println("   ${ANSI_GREEN}✓ cleaned $removed intermediate files${ANSI_RESET}")
    resultCard(finalName, outDir, sha, finalApk.length(), System.currentTimeMillis() - start)
}

// ---------------------------------------------------------------------------
// Analysis-only mode: profile the protection stack, pick the unpacker
// ---------------------------------------------------------------------------

private fun runAnalyzePipeline(apk: File) {
    banner()
    targetCard(apk)
    println()
    println(uiTop())
    println(uiRow("${ANSI_BOLD_GREEN}P R O G R A M   P R O F I L E${ANSI_RESET}"))
    println(uiBot())

    val profile = runWithSpinner(99, "Analyzing APK", 99) { Profiler.analyze(apk) }

    println()
    println(uiTop())
    println(uiRow("${ANSI_GREEN}IDENTITY${ANSI_RESET}"))
    val nativeList = profile.nativeLibs
    println(uiRow(" package:   ${profile.packageName ?: "(unknown)"}"))
    println(uiRow(" app class: ${profile.applicationCls ?: "(none)"}"))
    println(uiRow(" launcher:  ${profile.launcherActivity ?: "(none)"}"))
    println(uiRow(" native:    ${if (nativeList.isEmpty()) "none" else nativeList.joinToString(", ")}"))
    println(uiBot())

    println()
    println(uiTop())
    println(uiRow("${ANSI_BOLD_GREEN}PROTECTION LAYERS${ANSI_RESET}"))
    if (profile.layers.isEmpty()) {
        println(uiRow("  ${ANSI_GREEN}none detected - looks like a raw apk${ANSI_RESET}"))
    }
    for (layer in profile.layers) {
        val pct = "%.0f".format(layer.likelihood * 100)
        println(uiRow("  ${layer.name}  [${if (layer.likelihood > 0.8) ANSI_RED else if (layer.likelihood > 0.5) "\u001B[33m" else ANSI_GREEN}$pct%${ANSI_RESET}] ${layer.hits} hit(s)"))
        for (ev in layer.evidence) println(uiRow("      ~ $ev"))
    }
    if (profile.junkSuspects.isNotEmpty()) {
        println(uiRow("${ANSI_GREEN}JUNK/OFFUSCATION SUSPECTS${ANSI_RESET}"))
        for (j in profile.junkSuspects) println(uiRow("      ~ $j"))
    }
    println(uiBot())

    // Optional APKiD (YARA) booster -- folded in when available.
    val apkidHits = runWithSpinner(99, "APKiD YARA scan", 99) { ApkIdRunner.scan(apk) ?: emptyList() }
    if (apkidHits != null && apkidHits.isNotEmpty()) {
        println()
        println(uiTop())
        println(uiRow("${ANSI_BOLD_GREEN}APKiD (YARA)${ANSI_RESET}"))
        val byRule = apkidHits.distinctBy { it.rule to it.file }
        for (h in byRule.take(25)) {
            val note = if (h.notes.isEmpty()) "" else " -- ${h.notes}"
            println(uiRow("  ${h.rule}  ${ANSI_GREEN}@ ${cut(h.file, 30)}${ANSI_RESET}$note"))
        }
        if (byRule.size > 25) println(uiRow("  ... ${byRule.size - 25} more"))
        println(uiBot())
    }

    // Strategy recommendation
    println()
    println(uiTop())
    println(uiRow("${ANSI_BOLD_GREEN}R E C O M M E N D A T I O N${ANSI_RESET}"))
    val owned = Profiler.ownedStrategies()
    val ownedLayer = profile.layers.firstOrNull { it.strategy in owned || (it.strategy == "pairip" && RePairipTool.find() != null) }
    val fallback = profile.layers.firstOrNull()
    val embedded = profile.layers.firstOrNull { it.strategy == "embedded" }
    if (ownedLayer != null) {
        println(uiRow(" unpacker:  ${strategyLabel(ownedLayer.strategy)}"))
        println(uiRow(" run:       --mode ${ownedLayer.strategy}"))
    } else if (embedded != null) {
        val src = embedded.evidence.firstOrNull { it.contains("origin.apk") }
            ?.substringAfter("embedded app: ") ?: "assets/SignatureKiller/origin.apk"
        println(uiRow(" ${ANSI_BOLD_YELLOW}TRICK${ANSI_RESET}     fake / low-effort protection shell"))
        println(uiRow(" extract:   $src"))
        println(uiRow(" re-run:    --mode auto <path to extracted apk>"))
    } else if (fallback != null) {
        println(uiRow(" unpacker:  ${strategyLabel(fallback.strategy)} (external)"))
        println(uiRow(" tool:      ${fallback.tool ?: "?"}"))
        println(uiRow(" status:    vendored tool not wired yet; run manually"))
    } else {
        println(uiRow(" apk is raw - no unpacking needed"))
    }
    println(uiBot())
}

private fun strategyLabel(s: String) = when (s) {
    "dpt" -> "DPT Shell restore (static)"
    "lsparanoid" -> "LSParanoid deobfuscate (static)"
    "ark" -> "360 Jiagu / ArkShell dump (device)"
    "b2al" -> "B2Al proxy packer restore (static)"
    "pairip" -> "PairipProtect deprotection (RePairip)"
    "embedded" -> "extract embedded origin.apk (SignatureKiller re-pack)"
    "frida" -> "frida runtime dump (KeyDive/frida-dexdump)"
    "il2cpp" -> "Unity IL2CPP dump (Auto-Il2cppDumper)"
    "xamarin" -> "Xamarin assembly extract (pyxamstore)"
    "hermes" -> "Hermes bytecode dump (hermes_rs)"
    "flutter" -> "Flutter dump (blutter)"
    "native" -> "native analysis (d2c/dex2c)"
    else -> s
}

// ---------------------------------------------------------------------------
// UI helpers (Mobile Optimized "Open-Box" Design)
// ---------------------------------------------------------------------------

private fun banner() {
    println()
    println(uiTop())
    println(uiRow("${ANSI_BOLD_GREEN}U N P A C K E R   B Y   F A H A D${ANSI_RESET}"))
    println(uiRow("static restore . clean . rebuild"))
    println(uiRow("${ANSI_GREEN}github.com${ANSI_RESET}/0xgf18"))
    println(uiBot())
}

private fun targetCard(apk: File) {
    val sha = sha256(apk.readBytes())
    val entries = runCatching { ZipFile(apk).use { it.size() } }.getOrDefault(0)
    println()
    println(uiTop())
    println(uiRow("${ANSI_GREEN}TARGET:${ANSI_RESET}  ${cut(apk.name, 28)}"))
    println(uiRow("${ANSI_GREEN}SIZE:${ANSI_RESET}    ${fmtSize(apk.length())}"))
    println(uiRow("${ANSI_GREEN}ENTRIES:${ANSI_RESET} $entries"))
    println(uiRow("${ANSI_GREEN}SHA-256:${ANSI_RESET} ${cut(sha, 28)}"))
    println(uiBot())
}

private fun resultCard(finalName: String, outDir: File, sha: String, size: Long, ms: Long) {
    println()
    println(uiTop())
    println(uiRow("${ANSI_BOLD_GREEN}R E S U L T${ANSI_RESET}"))
    println(uiRow(""))
    println(uiRow("DIR:  ${cut(outDir.name, 30)}"))
    println(uiRow("APK:  ${cut(finalName, 30)}"))
    println(uiRow("SIZE: ${fmtSize(size)}"))
    println(uiRow("SHA:  ${cut(sha, 30)}"))
    println(uiRow(""))
    println(uiRow("${ANSI_GREEN}COMPLETED IN ${fmtMs(ms)}${ANSI_RESET}"))
    println(uiBot())
}

private fun errorCard(msg: String) {
    System.err.println(msg)
    println(uiTop())
    println(uiRow("${ANSI_RED}F A I L E D${ANSI_RESET}"))
    println(uiRow(""))
    for (raw in msg.lines()) {
        if (raw.isBlank()) continue
        for (wrapped in wrapText(raw, 42)) println(uiRow(wrapped))
    }
    println(uiBot())
}

/** word-wrap a single line to fit the mobile card width without losing content. */
private fun wrapText(s: String, width: Int): List<String> {
    val out = mutableListOf<String>()
    var cur = StringBuilder()
    for (w in s.split(" ")) {
        if (cur.isNotEmpty() && cur.length + 1 + w.length > width) {
            out.add(cur.toString())
            cur = StringBuilder(w)
        } else {
            if (cur.isNotEmpty()) cur.append(' ')
            cur.append(w)
        }
    }
    if (cur.isNotEmpty()) out.add(cur.toString())
    return if (out.isEmpty()) listOf("") else out
}

private fun stageHead(n: Int, title: String) {
    println("\n ${ANSI_BOLD_GREEN}[$n/5] $title${ANSI_RESET}")
}

private fun <T> runQuiet(n: Int, title: String, total: Int = 5, block: () -> T): T {
    println()
    println("  [$n/$total] $title...")
    return block()
}

private fun <T> runWithSpinner(n: Int, title: String, total: Int = 5, block: () -> T): T {
    println()
    val frames = arrayOf("|", "/", "-", "\\")
    var running = true
    var result: T? = null
    var exception: Exception? = null

    val thread = Thread {
        var i = 0
        while (running) {
            print("\r ${ANSI_BOLD_GREEN}[$n/$total] ${frames[i % frames.size]} $title...${ANSI_RESET}  ")
            System.out.flush()
            try { Thread.sleep(80) } catch (_: Exception) {}
            i++
        }
    }
    thread.start()

    try {
        result = block()
    } catch (e: Exception) {
        exception = e
    } finally {
        running = false
        thread.join()
        print("\r\u001B[K") // Clear line
    }

    if (exception != null) throw exception
    return result!!
}

private fun stageDone(ms: Long) {
    println("   ${ANSI_GREEN}✓ done (${fmtMs(ms)})${ANSI_RESET}")
}

private fun progressBar(frac: Double): String {
    val w = 8
    val filled = (frac * w).toInt().coerceIn(0, w)
    return "#".repeat(filled) + ".".repeat(w - filled)
}

private fun cut(s: String, max: Int): String {
    if (s.length <= max) return s
    val head = (max / 2) - 1
    return s.take(head) + "..." + s.takeLast(max - head - 3)
}

private fun fmtSize(bytes: Long): String = when {
    bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1048576.0)
    bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

private fun fmtMs(ms: Long): String =
    if (ms < 1000) "$ms ms" else "%.2f s".format(ms / 1000.0)

// Open-Box styling to prevent wrapping issues on mobile devices
private fun uiTop() = " " + (if (utf8) "╭" else "+") + (if (utf8) "─" else "-").repeat(UI_W)
private fun uiBot() = " " + (if (utf8) "╰" else "+") + (if (utf8) "─" else "-").repeat(UI_W)
private fun uiRow(s: String) = " " + (if (utf8) "│" else "|") + " $s"

private fun sha256(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

private data class ResolvedKey(val key: com.dpt.unpack.crack.RecoveredKey?)

private fun determineAesKey(
    apk: File, aesKeyHex: String?, crack: Boolean, debug: Boolean,
    pkgOverride: String?, buildKeyOverride: String?, buildKeysFile: String?, hexToBytes: (String) -> ByteArray?
): ResolvedKey {
    if (aesKeyHex != null && !crack) return ResolvedKey(null)
    val extraKeys = ArrayList<String>()
    buildKeyOverride?.let { extraKeys.add(it) }
    buildKeysFile?.let { path -> File(path).takeIf { it.isFile }?.readLines()?.map { it.trim() }?.filter { it.isNotEmpty() }?.let(extraKeys::addAll) }
    try {
        val recovered = KeyRecovery.recover(apk, extraKeys, listOfNotNull(pkgOverride), debug)
        return if (recovered.isEmpty()) ResolvedKey(null) else ResolvedKey(recovered.first())
    } catch (_: Exception) { return ResolvedKey(null) }
}

private fun pickBestCandidate(
    candidates: List<com.dpt.unpack.code.CodeStoreCandidate>, payloadDexes: List<com.dpt.unpack.detection.PayloadDex>, capacitiesByDex: List<Map<Long, Int>>
): CandidateScore = candidates.mapIndexed { idx, cand ->
    var score = 0.0; var matched = 0; var total = 0
    for ((dexIndex, records) in cand.sections) {
        val caps = capacitiesByDex.getOrNull(dexIndex)
        for (rec in records) {
            total++
            val cap = caps?.get(rec.methodIdx)
            when {
                cap == null -> score -= 0.5
                rec.insns.size == cap -> { score += 1.0; matched++ }
                rec.insns.size > cap -> score -= 2.0
                else -> score -= 0.25
            }
        }
    }
    CandidateScore(idx, cand.layoutDesc, score, matched, total)
}.maxByOrNull { it.score } ?: throw IllegalStateException("no candidates")

private fun ByteArray.writeTo(file: File) { file.writeBytes(this) }
private fun com.dpt.unpack.restore.RestoreResult.nameFor(dexIndex: Int): String = if (dexIndex == 0) "classes.dex" else "classes${dexIndex + 1}.dex"
