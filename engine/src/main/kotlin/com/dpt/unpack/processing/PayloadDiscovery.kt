package com.dpt.unpack.processing

import java.io.File

/**
 * Discovers and classifies artifacts produced by static and dynamic analysis engines.
 *
 * Distinguishes between:
 * - Original APK files
 * - Extracted files
 * - Runtime-generated artifacts
 * - DEX payloads
 * - Native libraries
 * - Unknown artifacts
 */
object PayloadDiscovery {

    private val NATIVE_EXTENSIONS = setOf("so")
    private val MANIFEST_NAMES = setOf("AndroidManifest.xml")
    private val RESOURCE_DIRS = setOf("res", "res_", "resources.arsc")

    /**
     * Discover all artifacts in a workspace directory.
     *
     * @param workspaceDir the workspace root directory
     * @param source hint about which engine produced these artifacts
     * @return list of classified artifacts
     */
    fun discover(workspaceDir: File, source: ArtifactSource = ArtifactSource.UNKNOWN): List<Artifact> {
        if (!workspaceDir.isDirectory) return emptyList()

        val artifacts = mutableListOf<Artifact>()
        val visited = mutableSetOf<String>()

        fun scanDir(dir: File) {
            val children = dir.listFiles() ?: return
            for (child in children) {
                when {
                    child.isDirectory -> scanDir(child)
                    child.isFile && child.absolutePath !in visited -> {
                        visited.add(child.absolutePath)
                        val artifact = classifyFile(child, workspaceDir, source)
                        if (artifact != null) {
                            artifacts.add(artifact)
                        }
                    }
                }
            }
        }

        scanDir(workspaceDir)
        return artifacts
    }

    /**
     * Discover artifacts specifically from the output directory.
     */
    fun discoverOutput(workspaceDir: File, source: ArtifactSource = ArtifactSource.UNKNOWN): List<Artifact> {
        val outputDir = workspaceDir.resolve("output")
        return if (outputDir.isDirectory) discover(outputDir, source) else emptyList()
    }

    /**
     * Discover artifacts from the input directory (original APK contents).
     */
    fun discoverInput(workspaceDir: File): List<Artifact> {
        val inputDir = workspaceDir.resolve("input")
        return if (inputDir.isDirectory) discover(inputDir, ArtifactSource.MANUAL) else emptyList()
    }

    /**
     * Classify a single file by its type and characteristics.
     */
    fun classifyFile(file: File, rootDir: File, source: ArtifactSource): Artifact? {
        if (!file.isFile || file.length() == 0L) return null

        val relPath = rootDir.toPath().relativize(file.toPath()).toString()
        val type = detectType(file)
        val meta = mutableMapOf<String, String>()
        meta["relativePath"] = relPath
        meta["extension"] = file.extension

        // Detect if this might be an original APK
        if (file.extension.equals("apk", ignoreCase = true)) {
            meta["isOriginalApk"] = "true"
        }

        return Artifact(
            file = file,
            type = type,
            source = source,
            name = file.name,
            size = file.length(),
            metadata = meta,
        )
    }

    /**
     * Detect the type of a file by examining extension and content.
     */
    fun detectType(file: File): ArtifactType {
        val ext = file.extension.lowercase()

        // DEX files
        if (ext == "dex") {
            return if (DexDiscovery.isDexFile(file)) ArtifactType.DEX else ArtifactType.UNKNOWN
        }

        // Native libraries
        if (ext == "so") {
            return if (isElfFile(file)) ArtifactType.NATIVE_LIB else ArtifactType.UNKNOWN
        }

        // Manifest
        if (file.name in MANIFEST_NAMES) {
            return ArtifactType.MANIFEST
        }

        // Resources
        if (file.name == "resources.arsc" || ext == "arsc") {
            return ArtifactType.RESOURCE
        }

        // Config/properties
        if (ext in setOf("xml", "json", "properties", "cfg", "conf", "txt")) {
            return ArtifactType.CONFIG
        }

        // Check if it's actually a DEX with wrong extension
        if (file.length() > 112) {
            try {
                file.inputStream().use { stream ->
                    val header = ByteArray(8)
                    val read = stream.read(header)
                    if (read >= 8 && DexDiscovery.isDexBytes(header)) {
                        return ArtifactType.DEX
                    }
                }
            } catch (_: Exception) {}
        }

        return ArtifactType.UNKNOWN
    }

    private fun isElfFile(file: File): Boolean {
        return try {
            file.inputStream().use { stream ->
                val header = ByteArray(4)
                val read = stream.read(header)
                read >= 4 && header[0] == 0x7F.toByte() &&
                    header[1] == 'E'.code.toByte() &&
                    header[2] == 'L'.code.toByte() &&
                    header[3] == 'F'.code.toByte()
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Filter artifacts by type.
     */
    fun byType(artifacts: List<Artifact>, type: ArtifactType): List<Artifact> =
        artifacts.filter { it.type == type }

    /**
     * Filter artifacts by source.
     */
    fun bySource(artifacts: List<Artifact>, source: ArtifactSource): List<Artifact> =
        artifacts.filter { it.source == source }

    /**
     * Get DEX artifacts only.
     */
    fun dexArtifacts(artifacts: List<Artifact>): List<Artifact> =
        byType(artifacts, ArtifactType.DEX)

    /**
     * Get native library artifacts only.
     */
    fun nativeArtifacts(artifacts: List<Artifact>): List<Artifact> =
        byType(artifacts, ArtifactType.NATIVE_LIB)

    /**
     * Generate a summary report of discovered artifacts.
     */
    fun summarize(artifacts: List<Artifact>): PayloadSummary {
        val byType = artifacts.groupBy { it.type }
        val totalSize = artifacts.sumOf { it.size }
        return PayloadSummary(
            totalArtifacts = artifacts.size,
            totalSizeBytes = totalSize,
            dexCount = byType[ArtifactType.DEX]?.size ?: 0,
            nativeLibCount = byType[ArtifactType.NATIVE_LIB]?.size ?: 0,
            resourceCount = byType[ArtifactType.RESOURCE]?.size ?: 0,
            manifestCount = byType[ArtifactType.MANIFEST]?.size ?: 0,
            configCount = byType[ArtifactType.CONFIG]?.size ?: 0,
            unknownCount = byType[ArtifactType.UNKNOWN]?.size ?: 0,
            bySource = artifacts.groupBy { it.source }.mapValues { it.value.size },
        )
    }
}

data class PayloadSummary(
    val totalArtifacts: Int,
    val totalSizeBytes: Long,
    val dexCount: Int,
    val nativeLibCount: Int,
    val resourceCount: Int,
    val manifestCount: Int,
    val configCount: Int,
    val unknownCount: Int,
    val bySource: Map<ArtifactSource, Int>,
)
