package com.dpt.unpack.processing

import com.dpt.unpack.validate.DexValidator
import java.io.File

/**
 * Discovers DEX files in analysis workspaces and output directories.
 *
 * Searches:
 * - Direct children of the workspace output directory
 * - Recursively within workspace subdirectories
 * - Standard DEX naming patterns (classes.dex, classes2.dex, etc.)
 * - Any .dex file regardless of name
 */
object DexDiscovery {

    private val DEX_EXTENSIONS = setOf("dex")
    private val STANDARD_DEX_NAMES = (1..10).map { i -> "classes${if (i == 1) "" else i}.dex" }

    /**
     * Discover all DEX files in a directory tree.
     *
     * @param rootDir the root directory to search
     * @param recursive whether to search subdirectories (default true)
     * @return list of discovered DEX artifacts
     */
    fun discover(rootDir: File, recursive: Boolean = true): List<Artifact> {
        if (!rootDir.isDirectory) return emptyList()

        val artifacts = mutableListOf<Artifact>()
        val visited = mutableSetOf<String>()

        fun scanDir(dir: File) {
            val children = dir.listFiles() ?: return
            for (child in children) {
                if (child.isDirectory && recursive) {
                    scanDir(child)
                } else if (child.isFile && isDexFile(child) && child.absolutePath !in visited) {
                    visited.add(child.absolutePath)
                    val artifact = classifyDex(child, rootDir)
                    artifacts.add(artifact)
                }
            }
        }

        scanDir(rootDir)
        return artifacts.sortedBy { it.name }
    }

    /**
     * Discover DEX files with standard naming (classes.dex, classes2.dex, ...).
     *
     * @param dir the directory to search
     * @return list of standard-named DEX artifacts
     */
    fun discoverStandard(dir: File): List<Artifact> {
        if (!dir.isDirectory) return emptyList()
        val artifacts = mutableListOf<Artifact>()
        for (name in STANDARD_DEX_NAMES) {
            val file = dir.resolve(name)
            if (file.isFile && isDexFile(file)) {
                artifacts.add(classifyDex(file, dir))
            }
        }
        return artifacts
    }

    /**
     * Discover DEX files inside a specific subdirectory (e.g., "output/").
     */
    fun discoverInOutput(workspaceDir: File): List<Artifact> {
        val outputDir = workspaceDir.resolve("output")
        return if (outputDir.isDirectory) discover(outputDir) else emptyList()
    }

    /**
     * Quick check if a file is a DEX file based on extension and magic bytes.
     */
    fun isDexFile(file: File): Boolean {
        if (!file.isFile) return false
        val ext = file.extension.lowercase()
        if (ext !in DEX_EXTENSIONS) return false
        return try {
            file.inputStream().use { stream ->
                val header = ByteArray(8)
                val read = stream.read(header)
                read >= 8 && DexValidator.isDex(header)
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Quick check if a byte array is a DEX file.
     */
    fun isDexBytes(data: ByteArray): Boolean = DexValidator.isDex(data)

    /**
     * Get the DEX index from a standard filename (classes.dex → 1, classes2.dex → 2, etc.)
     * Returns null for non-standard names.
     */
    fun dexIndex(filename: String): Int? {
        val base = filename.removeSuffix(".dex")
        return when {
            base == "classes" -> 1
            base.startsWith("classes") -> base.removePrefix("classes").toIntOrNull()
            else -> null
        }
    }

    /**
     * Validate a discovered DEX file and return validation details.
     */
    fun validateDex(file: File): DexValidationResult {
        if (!file.exists()) {
            return DexValidationResult(
                valid = false,
                file = file,
                errors = listOf("File does not exist"),
            )
        }

        val bytes = try {
            file.readBytes()
        } catch (e: Exception) {
            return DexValidationResult(
                valid = false,
                file = file,
                errors = listOf("Cannot read file: ${e.message}"),
            )
        }

        val errors = DexValidator.validate(bytes)
        return DexValidationResult(
            valid = errors.isEmpty(),
            file = file,
            fileSize = bytes.size.toLong(),
            errors = errors,
        )
    }

    private fun classifyDex(file: File, rootDir: File): Artifact {
        val relPath = rootDir.toPath().relativize(file.toPath()).toString()
        val index = dexIndex(file.name)
        val meta = mutableMapOf<String, String>()
        meta["relativePath"] = relPath
        if (index != null) meta["dexIndex"] = index.toString()
        meta["extension"] = file.extension

        return Artifact(
            file = file,
            type = ArtifactType.DEX,
            source = ArtifactSource.UNKNOWN,
            name = file.name,
            size = file.length(),
            metadata = meta,
        )
    }
}

/**
 * Result of validating a DEX file.
 */
data class DexValidationResult(
    val valid: Boolean,
    val file: File,
    val fileSize: Long = 0,
    val errors: List<String> = emptyList(),
)
