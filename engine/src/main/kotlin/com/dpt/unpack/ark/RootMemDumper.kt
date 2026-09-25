package com.dpt.unpack.ark

import java.io.File

/**
 * Root-based memory DEX scanner for on-device dynamic unpacking.
 *
 * Uses /proc/pid/mem + /proc/pid/maps to scan a running app's memory
 * for DEX files decrypted in-memory by packers like B2Al dynamic.
 *
 * No Frida required — works with just root (su) access.
 */
object RootMemDumper {

    private const val MIN_DEX_SIZE = 112
    private const val MAX_DEX_SIZE = 50 * 1024 * 1024
    private val DEX_MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0a)

    data class DumpedDex(val name: String, val bytes: ByteArray)

    /**
     * Scans a running app's memory for DEX files and dumps them.
     */
    fun dumpFromMemory(device: ArkDevice, pkg: String, dumpDir: File): List<DumpedDex> {
        dumpDir.mkdirs()

        val pid = device.shell("pidof $pkg").text.trim().lines().firstOrNull { it.isNotEmpty() }
            ?: throw IllegalStateException("$pkg is not running — launch the app first")

        val mapsResult = device.shell("cat /proc/$pid/maps")
        if (mapsResult.exit != 0) throw IllegalStateException("cannot read /proc/$pid/maps")

        val regions = parseMaps(mapsResult.text)
        if (regions.isEmpty()) throw IllegalStateException("no readable memory regions for pid=$pid")

        val results = mutableListOf<DumpedDex>()
        val seenSizes = mutableSetOf<Int>()

        for (region in regions) {
            val found = scanRegionWithDd(device, pid, region, dumpDir, seenSizes)
            results.addAll(found)
        }

        if (results.isEmpty()) {
            throw IllegalStateException(
                "no DEX files found in memory of $pkg (pid=$pid). " +
                    "The app may not have decrypted its DEX yet — try launching it manually first."
            )
        }

        return results
    }

    private data class MemRegion(val start: Long, val end: Long, val perms: String, val path: String?)

    private fun parseMaps(mapsText: String): List<MemRegion> {
        return mapsText.lines().mapNotNull { line ->
            val parts = line.split(" ", limit = 6)
            if (parts.size < 2) return@mapNotNull null
            val addrParts = parts[0].split("-")
            if (addrParts.size != 2) return@mapNotNull null
            val start = try { addrParts[0].toLong(16) } catch (_: Exception) { return@mapNotNull null }
            val end = try { addrParts[1].toLong(16) } catch (_: Exception) { return@mapNotNull null }
            val perms = parts[1]
            val path = parts.getOrNull(5)?.trim()?.takeIf { it.isNotEmpty() && it != "[stack]" && it != "[vdso]" }
            MemRegion(start, end, perms, path)
        }.filter { r ->
            r.perms.startsWith("r") && (r.end - r.start) in 4096..MAX_DEX_SIZE.toLong()
        }.sortedByDescending { it.end - it.start }
    }

    /**
     * Reads the first 4096 bytes of a region via dd, checks for DEX magic.
     * If found, reads the full DEX from the header's fileSize field.
     */
    private fun scanRegionWithDd(
        device: ArkDevice,
        pid: String,
        region: MemRegion,
        dumpDir: File,
        seenSizes: MutableSet<Int>,
    ): List<DumpedDex> {
        val results = mutableListOf<DumpedDex>()
        val regionSize = (region.end - region.start).toInt()
        val probeSize = minOf(4096, regionSize)

        // Read first page of region as base64
        val b64 = device.shell(
            "dd if=/proc/$pid/mem bs=1 skip=${region.start} count=$probeSize 2>/dev/null | base64"
        ).text.trim()
        if (b64.isEmpty()) return results

        val headerBytes = try {
            java.util.Base64.getDecoder().decode(b64)
        } catch (_: Exception) { return results }

        if (headerBytes.size < 4) return results
        if (headerBytes[0] != DEX_MAGIC[0] || headerBytes[1] != DEX_MAGIC[1] ||
            headerBytes[2] != DEX_MAGIC[2] || headerBytes[3] != DEX_MAGIC[3]) {
            return results
        }

        // DEX header: file_size is at offset 32, 4 bytes little-endian
        if (headerBytes.size < 36) return results
        val fileSize = (headerBytes[32].toInt() and 0xFF) or
            ((headerBytes[33].toInt() and 0xFF) shl 8) or
            ((headerBytes[34].toInt() and 0xFF) shl 16) or
            ((headerBytes[35].toInt() and 0xFF) shl 24)

        if (fileSize < MIN_DEX_SIZE || fileSize > MAX_DEX_SIZE) return results
        if (fileSize in seenSizes) return results
        seenSizes.add(fileSize)

        // Read the full DEX
        val fullB64 = device.shell(
            "dd if=/proc/$pid/mem bs=1 skip=${region.start} count=$fileSize 2>/dev/null | base64"
        ).text.trim()
        if (fullB64.isEmpty()) return results

        val dexBytes = try {
            java.util.Base64.getDecoder().decode(fullB64)
        } catch (_: Exception) { return results }

        // Verify it's still a valid DEX
        if (dexBytes.size < 4 || dexBytes[0] != DEX_MAGIC[0]) return results

        val name = "memdump_${region.start}_${results.size}.dex"
        val outFile = File(dumpDir, name)
        outFile.writeBytes(dexBytes)
        results.add(DumpedDex(name, dexBytes))

        return results
    }
}
