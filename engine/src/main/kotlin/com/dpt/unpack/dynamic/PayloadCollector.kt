package com.dpt.unpack.dynamic

import com.dpt.unpack.privilege.PrivilegeProvider
import java.io.File

/**
 * Collects runtime artifacts (DEX files, native libraries, memory dumps)
 * from a running or recently-running target application.
 *
 * Implementations may use different strategies:
 * - Filesystem scanning (/proc/<pid>/fd, /data/data/<pkg>/)
 * - Memory mapping extraction
 * - Dumpsys-based collection
 * - Frida-based collection (when available)
 *
 * Collectors are protector-specific. The framework provides the interface;
 * individual protector collectors plug in here.
 */
interface PayloadCollector {

    /**
     * Human-readable name of this collector (e.g. "FD Scanner", "Frida Dumper").
     */
    val name: String

    /**
     * Check whether this collector can operate with the given privilege level.
     */
    fun canOperateWith(level: com.dpt.unpack.privilege.PrivilegeLevel): Boolean

    /**
     * Collect payloads from the target application.
     *
     * @param packageName the target package name
     * @param pid the process ID of the running target
     * @param workspace the workspace to store collected artifacts
     * @param logger structured logger for progress reporting
     * @return list of collected artifact files (may be empty if nothing was recovered)
     */
    fun collect(
        packageName: String,
        pid: Int,
        workspace: AnalysisWorkspace,
        logger: AnalysisLogger,
    ): List<CollectedPayload>
}

/**
 * A single collected payload artifact.
 */
data class CollectedPayload(
    /** Path to the collected file in the workspace. */
    val file: File,
    /** Type of payload (e.g., "dex", "so", "memdump"). */
    val type: PayloadType,
    /** Confidence that this is a valid payload (0.0 to 1.0). */
    val confidence: Double,
    /** Source description (e.g., "/proc/1234/fd/7"). */
    val source: String,
    /** Additional metadata. */
    val metadata: Map<String, String> = emptyMap(),
)

enum class PayloadType {
    DEX,
    NATIVE_LIB,
    MEMORY_DUMP,
    CONFIG,
    OTHER,
}

/**
 * FD-based payload collector. Scans /proc/<pid>/fd for open DEX files
 * and extracts them. Works with root or Shizuku.
 */
class FdPayloadCollector : PayloadCollector {

    override val name: String = "FD Scanner"

    override fun canOperateWith(level: com.dpt.unpack.privilege.PrivilegeLevel): Boolean {
        return level == com.dpt.unpack.privilege.PrivilegeLevel.ROOT ||
               level == com.dpt.unpack.privilege.PrivilegeLevel.SHIZUKU
    }

    override fun collect(
        packageName: String,
        pid: Int,
        workspace: AnalysisWorkspace,
        logger: AnalysisLogger,
    ): List<CollectedPayload> {
        val payloads = mutableListOf<CollectedPayload>()
        logger.i(name, "Scanning /proc/$pid/fd for DEX files")

        val fdDir = File("/proc/$pid/fd")
        if (!fdDir.canRead()) {
            logger.w(name, "Cannot read /proc/$pid/fd — insufficient permissions")
            return emptyList()
        }

        val fdEntries = fdDir.listFiles()?.filter { it.isDirectory } ?: emptyList()
        logger.i(name, "Found ${fdEntries.size} file descriptors")

        var dexCount = 0
        for (fd in fdEntries) {
            try {
                val link = fd.canonicalPath
                if (!link.contains(".dex", ignoreCase = true) &&
                    !link.contains("memfd:", ignoreCase = true)) {
                    continue
                }
                dexCount++
                val data = fd.readBytes()
                if (data.size < 112) continue // DEX magic is at offset 0, minimum viable size

                val magic = String(data, 0, 8)
                if (!magic.startsWith("dex\n")) {
                    continue
                }

                val outputName = "fd_dex_${payloads.size}.dex"
                val outFile = workspace.recoveredDex(outputName)
                outFile.writeBytes(data)
                payloads.add(
                    CollectedPayload(
                        file = outFile,
                        type = PayloadType.DEX,
                        confidence = 0.9,
                        source = "/proc/$pid/fd/${fd.name} -> $link",
                        metadata = mapOf("size" to data.size.toString(), "magic" to magic.trim()),
                    )
                )
                logger.i(name, "Collected DEX: $outputName (${data.size} bytes) from $link")
            } catch (_: Exception) {
                // Skip unreadable FDs
            }
        }

        logger.i(name, "FD scan complete: $dexCount DEX candidates, ${payloads.size} valid payloads")
        return payloads
    }
}

/**
 * Filesystem-based collector. Scans the app's data directory for extracted
 * DEX files, native libraries, and other artifacts.
 */
class FilesystemPayloadCollector(
    private val provider: PrivilegeProvider,
) : PayloadCollector {

    override val name: String = "Filesystem Scanner"

    override fun canOperateWith(level: com.dpt.unpack.privilege.PrivilegeLevel): Boolean {
        return level == com.dpt.unpack.privilege.PrivilegeLevel.ROOT
    }

    override fun collect(
        packageName: String,
        pid: Int,
        workspace: AnalysisWorkspace,
        logger: AnalysisLogger,
    ): List<CollectedPayload> {
        val payloads = mutableListOf<CollectedPayload>()
        val dataDir = "/data/data/$packageName"
        logger.i(name, "Scanning $dataDir for artifacts")

        // Scan common directories for DEX files
        val scanDirs = listOf(
            "$dataDir/files",
            "$dataDir/cache",
            "$dataDir/databases",
            "$dataDir/app_dex",
            "$dataDir/app_lib",
        )

        for (dir in scanDirs) {
            val result = provider.exec("find $dir -name '*.dex' -o -name '*.so' 2>/dev/null")
            if (result is com.dpt.unpack.privilege.PrivilegeResult.Success) {
                val files = result.output.lines().filter { it.isNotBlank() }
                for (filePath in files) {
                    try {
                        val catResult = provider.exec("cat $filePath")
                        if (catResult is com.dpt.unpack.privilege.PrivilegeResult.Success) {
                            val data = catResult.output.toByteArray()
                            val isDex = data.size > 112 && String(data, 0, 8).startsWith("dex\n")
                            val isSo = data.size > 4 && data[0] == 0x7f.toByte() &&
                                       data[1] == 'E'.code.toByte() &&
                                       data[2] == 'L'.code.toByte() &&
                                       data[3] == 'F'.code.toByte()

                            if (isDex || isSo) {
                                val ext = if (isDex) ".dex" else ".so"
                                val outputName = "fs_${payloads.size}$ext"
                                val outFile = workspace.outputDir.resolve(outputName)
                                outFile.writeBytes(data)
                                payloads.add(
                                    CollectedPayload(
                                        file = outFile,
                                        type = if (isDex) PayloadType.DEX else PayloadType.NATIVE_LIB,
                                        confidence = if (isDex) 0.8 else 0.7,
                                        source = filePath,
                                        metadata = mapOf("size" to data.size.toString()),
                                    )
                                )
                                logger.i(name, "Collected $ext: $outputName (${data.size} bytes) from $filePath")
                            }
                        }
                    } catch (_: Exception) {
                        // Skip unreadable files
                    }
                }
            }
        }

        logger.i(name, "Filesystem scan complete: ${payloads.size} artifacts collected")
        return payloads
    }
}
