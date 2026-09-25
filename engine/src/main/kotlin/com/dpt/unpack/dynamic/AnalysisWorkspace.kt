package com.dpt.unpack.dynamic

import java.io.File
import java.nio.file.Files
import java.util.UUID

/**
 * Isolated workspace for a single dynamic analysis session.
 *
 * Structure:
 * <root>/
 *   ├── input/          # Copy of the original APK
 *   ├── output/         # Recovered/collected artifacts
 *   ├── work/           # Temporary analysis files
 *   ├── logs/           # Captured logcat, traces, etc.
 *   └── metadata.json   # Session metadata
 *
 * Workspaces are created in a base directory (typically the app's cache)
 * and are identified by a unique session ID.
 */
class AnalysisWorkspace private constructor(
    val sessionId: String,
    val rootDir: File,
) {
    val inputDir: File get() = rootDir.resolve("input")
    val outputDir: File get() = rootDir.resolve("output")
    val workDir: File get() = rootDir.resolve("work")
    val logsDir: File get() = rootDir.resolve("logs")

    fun inputApk(): File = inputDir.resolve("target.apk")
    fun recoveredDex(index: Int): File = outputDir.resolve("classes${if (index == 1) "" else index}.dex")
    fun recoveredDex(name: String): File = outputDir.resolve(name)
    fun logcatFile(): File = logsDir.resolve("logcat.txt")
    fun metadataFile(): File = rootDir.resolve("metadata.json")

    /**
     * Initialize the workspace directory structure.
     */
    fun prepare(): Result<Unit> = runCatching {
        for (dir in listOf(inputDir, outputDir, workDir, logsDir)) {
            dir.mkdirs()
            require(dir.isDirectory) { "Failed to create ${dir.absolutePath}" }
        }
    }

    /**
     * Copy an APK into the workspace input directory.
     */
    fun stageApk(sourceApk: File): Result<File> = runCatching {
        require(sourceApk.exists()) { "APK does not exist: ${sourceApk.absolutePath}" }
        val dest = inputApk()
        sourceApk.copyTo(dest, overwrite = true)
        dest
    }

    /**
     * List all collected output artifacts.
     */
    fun listArtifacts(): List<File> {
        return outputDir.listFiles()?.toList()?.filter { it.isFile }?.sortedBy { it.name } ?: emptyList()
    }

    /**
     * Get total size of all artifacts in bytes.
     */
    fun artifactSize(): Long {
        return listArtifacts().sumOf { it.length() }
    }

    /**
     * Clean the work directory (not input or output).
     */
    fun cleanWork() {
        workDir.listFiles()?.forEach { it.deleteRecursively() }
    }

    /**
     * Delete the entire workspace.
     */
    fun destroy() {
        rootDir.deleteRecursively()
    }

    companion object {
        private const val TAG = "Workspace"

        /**
         * Create a new workspace under the given base directory.
         *
         * @param baseDir parent directory for workspaces (e.g., app cache)
         * @param sessionId optional custom session ID; auto-generated if null
         */
        fun create(baseDir: File, sessionId: String? = null): AnalysisWorkspace {
            val id = sessionId ?: "dyn-${UUID.randomUUID().toString().take(12)}"
            val root = baseDir.resolve("workspaces").resolve(id)
            return AnalysisWorkspace(sessionId = id, rootDir = root)
        }

        /**
         * Open an existing workspace by session ID.
         */
        fun open(baseDir: File, sessionId: String): AnalysisWorkspace? {
            val root = baseDir.resolve("workspaces").resolve(sessionId)
            return if (root.isDirectory) AnalysisWorkspace(sessionId, root) else null
        }

        /**
         * List all existing workspaces in the base directory.
         */
        fun list(baseDir: File): List<AnalysisWorkspace> {
            val workspacesDir = baseDir.resolve("workspaces")
            if (!workspacesDir.isDirectory) return emptyList()
            return workspacesDir.listFiles()
                ?.filter { it.isDirectory }
                ?.mapNotNull { dir -> dir.listFiles()?.find { it.name == "metadata.json" }?.let { AnalysisWorkspace(dir.name, dir) } }
                ?.sortedByDescending { it.sessionId }
                ?: emptyList()
        }
    }
}
