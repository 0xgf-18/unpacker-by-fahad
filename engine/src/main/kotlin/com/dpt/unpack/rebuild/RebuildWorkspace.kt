package com.dpt.unpack.rebuild

import java.io.File
import java.util.UUID

/**
 * Isolated workspace for a single rebuild job.
 *
 * Structure:
 * <root>/
 *   ├── input/          # Copy of the original APK
 *   ├── patched/        # Processed DEX files to install
 *   ├── manifest/       # Restored AndroidManifest.xml
 *   ├── output/         # Rebuilt APK
 *   └── temp/           # Intermediate files (cleaned after completion)
 *
 * Workspaces are created under a base directory and identified by job ID.
 */
class RebuildWorkspace private constructor(
    val jobId: String,
    val rootDir: File,
) {
    val inputDir: File get() = rootDir.resolve("input")
    val patchedDir: File get() = rootDir.resolve("patched")
    val manifestDir: File get() = rootDir.resolve("manifest")
    val outputDir: File get() = rootDir.resolve("output")
    val tempDir: File get() = rootDir.resolve("temp")

    fun inputApk(): File = inputDir.resolve("original.apk")
    fun manifestFile(): File = manifestDir.resolve("AndroidManifest.xml")
    fun outputApk(): File = outputDir.resolve("rebuilt.apk")

    /**
     * Initialize the workspace directory structure.
     */
    fun prepare(): Result<Unit> = runCatching {
        for (dir in listOf(inputDir, patchedDir, manifestDir, outputDir, tempDir)) {
            dir.mkdirs()
            require(dir.isDirectory) { "Failed to create ${dir.absolutePath}" }
        }
    }

    /**
     * Copy the original APK into the workspace.
     */
    fun stageApk(sourceApk: File): Result<File> = runCatching {
        require(sourceApk.exists()) { "APK does not exist: ${sourceApk.absolutePath}" }
        val dest = inputApk()
        sourceApk.copyTo(dest, overwrite = true)
        dest
    }

    /**
     * Stage a DEX file into the patched directory.
     */
    fun stageDex(sourceDex: File): Result<File> = runCatching {
        require(sourceDex.exists()) { "DEX does not exist: ${sourceDex.absolutePath}" }
        val dest = patchedDir.resolve(sourceDex.name)
        sourceDex.copyTo(dest, overwrite = true)
        dest
    }

    /**
     * Stage raw DEX bytes into the patched directory.
     */
    fun stageDex(name: String, bytes: ByteArray): Result<File> = runCatching {
        val dest = patchedDir.resolve(name)
        dest.writeBytes(bytes)
        dest
    }

    /**
     * Stage the restored manifest.
     */
    fun stageManifest(manifestBytes: ByteArray): Result<File> = runCatching {
        val dest = manifestFile()
        dest.writeBytes(manifestBytes)
        dest
    }

    /**
     * List all staged DEX files.
     */
    fun listStagedDex(): List<File> {
        val dexName = Regex("classes\\d*\\.dex")
        return patchedDir.listFiles()
            ?.filter { it.isFile && it.name.matches(dexName) }
            ?.sortedBy { f ->
                if (f.name == "classes.dex") 0
                else f.name.removePrefix("classes").removeSuffix(".dex").toIntOrNull() ?: Int.MAX_VALUE
            }
            ?: emptyList()
    }

    /**
     * Clean temporary files.
     */
    fun cleanTemp() {
        tempDir.listFiles()?.forEach { it.deleteRecursively() }
    }

    /**
     * Destroy the entire workspace.
     */
    fun destroy() {
        rootDir.deleteRecursively()
    }

    companion object {
        /**
         * Create a new rebuild workspace.
         *
         * @param baseDir parent directory for workspaces
         * @param jobId optional custom job ID
         */
        fun create(baseDir: File, jobId: String? = null): RebuildWorkspace {
            val id = jobId ?: "rebuild-${UUID.randomUUID().toString().take(12)}"
            val root = baseDir.resolve("rebuild-workspaces").resolve(id)
            return RebuildWorkspace(jobId = id, rootDir = root)
        }

        /**
         * Open an existing workspace by job ID.
         */
        fun open(baseDir: File, jobId: String): RebuildWorkspace? {
            val root = baseDir.resolve("rebuild-workspaces").resolve(jobId)
            return if (root.isDirectory) RebuildWorkspace(jobId, root) else null
        }
    }
}
