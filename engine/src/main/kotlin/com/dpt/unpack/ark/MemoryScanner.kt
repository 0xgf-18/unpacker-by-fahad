package com.dpt.unpack.ark

/**
 * Memory scanning module for DEX header detection in process memory.
 * Based on research: T06 (Memory Scanning for DEX Headers).
 *
 * Scans /proc/pid/maps for DEX magic bytes and extracts DEX images from memory regions.
 * Useful for detecting unpacked DEX that hasn't been written to disk.
 *
 * Features:
 * - DEX header detection (magic bytes: "dex\n035\0")
 * - Memory region scanning
 * - DEX size validation
 * - Duplicate prevention
 */
object MemoryScanner {

    /** DEX magic bytes: "dex\n035\0" */
    private val DEX_MAGIC = byteArrayOf(
        0x64, 0x65, 0x78, 0x0a, // "dex\n"
        0x30, 0x33, 0x35, 0x00  // "035\0"
    )

    /** Minimum DEX file size (header only). */
    private const val MIN_DEX_SIZE = 112

    /** Maximum DEX file size (100MB). */
    private const val MAX_DEX_SIZE = 100 * 1024 * 1024

    data class DexHeader(
        val magic: ByteArray,
        val checksum: Int,
        val signature: ByteArray,
        val fileSize: Int,
        val headerSize: Int,
        val endianTag: Int,
        val mapOff: Int,
        val stringIdsSize: Int,
        val typeIdsSize: Int,
        val protoIdsSize: Int,
        val fieldIdsSize: Int,
        val methodIdsSize: Int,
        val classDefsSize: Int,
    )

    data class MemoryRegion(
        val address: Long,
        val size: Long,
        val permissions: String,
        val path: String?,
    )

    fun parseDexHeader(bytes: ByteArray): DexHeader? {
        if (bytes.size < MIN_DEX_SIZE) return null
        for (i in 0 until 8) {
            if (bytes[i] != DEX_MAGIC[i]) return null
        }
        return DexHeader(
            magic = bytes.copyOf(8),
            checksum = readInt(bytes, 8),
            signature = bytes.copyOfRange(12, 32),
            fileSize = readInt(bytes, 32),
            headerSize = readInt(bytes, 36),
            endianTag = readInt(bytes, 40),
            mapOff = readInt(bytes, 44),
            stringIdsSize = readInt(bytes, 48),
            typeIdsSize = readInt(bytes, 52),
            protoIdsSize = readInt(bytes, 56),
            fieldIdsSize = readInt(bytes, 60),
            methodIdsSize = readInt(bytes, 64),
            classDefsSize = readInt(bytes, 68),
        )
    }

    fun validateDexHeader(header: DexHeader): Boolean {
        if (header.fileSize < header.headerSize) return false
        if (header.headerSize != 0x70) return false
        if (header.endianTag != 0x12345678 && header.endianTag != 0x78563412) return false
        if (header.mapOff < header.headerSize || header.mapOff >= header.fileSize) return false
        return true
    }

    fun isDexMagic(bytes: ByteArray): Boolean {
        if (bytes.size < 8) return false
        for (i in 0 until 8) {
            if (bytes[i] != DEX_MAGIC[i]) return false
        }
        return true
    }

    private fun readInt(bytes: ByteArray, offset: Int): Int {
        return (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }

    private const val D = "$" // Dollar sign shorthand for Frida scripts

    fun generateFridaScanScript(): String {
        val d = D
        return """
(function() {
    var DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00];
    var outputDir = "/data/local/tmp/frida_dumps";
    var dexIndex = 0;

    function ensureDir(dir) {
        var Runtime = Java.use("java.lang.Runtime");
        var runtime = Runtime.getRuntime();
        runtime.exec("mkdir -p " + dir);
    }

    function dumpDexAtAddress(address, size) {
        ensureDir(outputDir);
        var outFile = outputDir + "/memscan_" + dexIndex + ".dex";
        dexIndex++;
        try {
            var data = Memory.readByteArray(address, size);
            var File = Java.use("java.io.File");
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            var file = File.${d}new(outFile);
            var fos = FileOutputStream.${d}new(file);
            fos.write(data);
            fos.close();
            send({type: "memscan_dumped", path: outFile, address: address.toString(), size: size});
        } catch(e) {}
    }

    function scanForDexHeaders() {
        var ranges = Process.enumerateRanges("r--");
        var found = [];
        for (var i = 0; i < ranges.length; i++) {
            var range = ranges[i];
            try {
                for (var offset = 0; offset < range.size - 8; offset += 4096) {
                    var base = range.base.add(offset);
                    var magic = Memory.readByteArray(base, 8);
                    var magicArr = new Uint8Array(magic);
                    var match = true;
                    for (var j = 0; j < 8; j++) {
                        if (magicArr[j] !== DEX_MAGIC[j]) { match = false; break; }
                    }
                    if (match) {
                        try {
                            var fileSize = Memory.readU32(base.add(32));
                            if (fileSize > 112 && fileSize < 100 * 1024 * 1024) {
                                var alignedSize = (fileSize + 4095) & ~4095;
                                dumpDexAtAddress(base, Math.min(alignedSize, range.size - offset));
                                found.push({address: base.toString(), size: fileSize});
                            }
                        } catch(e) {}
                    }
                }
            } catch(e) {}
        }
        return found;
    }

    Java.perform(function() {
        send({type: "memory_scan_starting"});
        var results = scanForDexHeaders();
        send({type: "memory_scan_complete", found: results.length, details: results});
    });
})();
""".trimIndent()
    }

    fun generateClassLoaderHookScript(): String {
        val d = D
        return """
(function() {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
    var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");

    var dexIndex = 0;
    var outputDir = "/data/local/tmp/frida_dumps";

    function ensureDir(dir) {
        var Runtime = Java.use("java.lang.Runtime");
        var runtime = Runtime.getRuntime();
        runtime.exec("mkdir -p " + dir);
    }

    function dumpDex(path, dexBytes) {
        ensureDir(outputDir);
        var outFile = outputDir + "/classloader_" + dexIndex + ".dex";
        dexIndex++;
        var File = Java.use("java.io.File");
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        var file = File.${d}new(outFile);
        var fos = FileOutputStream.${d}new(file);
        fos.write(dexBytes);
        fos.close();
        send({type: "classloader_dumped", path: outFile, size: dexBytes.length});
    }

    DexClassLoader.${d}init.implementation = function(dexPath, optimizedDir, librarySearchPath, parent) {
        send({type: "dex_loading", method: "DexClassLoader", path: dexPath});
        try {
            var File = Java.use("java.io.File");
            var file = File.${d}new(dexPath);
            if (file.exists()) {
                var fis = Java.use("java.io.FileInputStream").${d}new(file);
                var bytes = [];
                var buf = [];
                while ((buf = fis.read()) !== -1) {
                    bytes.push(buf);
                }
                fis.close();
                var byteArray = new Uint8Array(bytes);
                if (byteArray.length > 0 && byteArray[0] === 0x64 && byteArray[1] === 0x65 &&
                    byteArray[2] === 0x78 && byteArray[3] === 0x0a) {
                    dumpDex(dexPath, byteArray);
                }
            }
        } catch(e) {}
        return this.${d}init(dexPath, optimizedDir, librarySearchPath, parent);
    };

    PathClassLoader.${d}init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function(dexPath, parent) {
        send({type: "dex_loading", method: "PathClassLoader", path: dexPath});
        try {
            var File = Java.use("java.io.File");
            var file = File.${d}new(dexPath);
            if (file.exists()) {
                var fis = Java.use("java.io.FileInputStream").${d}new(file);
                var bytes = [];
                var buf = [];
                while ((buf = fis.read()) !== -1) {
                    bytes.push(buf);
                }
                fis.close();
                var byteArray = new Uint8Array(bytes);
                if (byteArray.length > 0 && byteArray[0] === 0x64 && byteArray[1] === 0x65 &&
                    byteArray[2] === 0x78 && byteArray[3] === 0x0a) {
                    dumpDex(dexPath, byteArray);
                }
            }
        } catch(e) {}
        return this.${d}init(dexPath, parent);
    };

    InMemoryDexClassLoader.${d}init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function(dexBuffer, parent) {
        send({type: "dex_loading", method: "InMemoryDexClassLoader", path: "memory"});
        try {
            var bytes = [];
            var buf = [];
            while (dexBuffer.hasRemaining()) {
                buf = dexBuffer.get();
                bytes.push(buf & 0xFF);
            }
            dexBuffer.rewind();
            var byteArray = new Uint8Array(bytes);
            if (byteArray.length > 0 && byteArray[0] === 0x64 && byteArray[1] === 0x65 &&
                byteArray[2] === 0x78 && byteArray[3] === 0x0a) {
                dumpDex("memory_buffer", byteArray);
            }
        } catch(e) {}
        return this.${d}init(dexBuffer, parent);
    };

    send({type: "classloader_hooks_installed"});
})();
""".trimIndent()
    }
}
