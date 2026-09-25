package com.dpt.unpack.processing

import com.dpt.unpack.validate.DexValidator
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Main DEX/payload processing pipeline.
 *
 * Orchestrates:
 * 1. Payload discovery — find all artifacts in workspace
 * 2. DEX discovery — find all DEX files
 * 3. DEX validation — verify each DEX
 * 4. Checksum repair — fix broken checksums where possible
 * 5. Multi-DEX ordering — establish correct DEX sequence
 * 6. Output normalization — copy to predictable output structure
 * 7. Result generation — structured processing results
 *
 * This processor is engine-agnostic. It operates on validated artifacts
 * regardless of which static or dynamic engine produced them.
 */
class PayloadProcessor(private val workspaceDir: File) {

    private val results = ConcurrentHashMap<String, ProcessingResult>()
    private val startTime = System.currentTimeMillis()

    /**
     * Process all artifacts in the workspace.
     *
     * @param source hint about which engine produced the artifacts
     * @param repairChecksums whether to attempt checksum repair (default true)
     * @return batch processing result
     */
    fun processAll(
        source: ArtifactSource = ArtifactSource.UNKNOWN,
        repairChecksums: Boolean = true,
    ): BatchProcessingResult {
        val processStart = System.currentTimeMillis()
        results.clear()

        // Step 1: Discover all payloads
        val allArtifacts = PayloadDiscovery.discover(workspaceDir, source)

        // Step 2: Process DEX artifacts
        val dexArtifacts = PayloadDiscovery.dexArtifacts(allArtifacts)
        for (dex in dexArtifacts) {
            processDex(dex, repairChecksums)
        }

        // Step 3: Process non-DEX artifacts (pass-through for now)
        for (artifact in allArtifacts) {
            if (artifact.type != ArtifactType.DEX) {
                processNonDex(artifact)
            }
        }

        val totalTime = System.currentTimeMillis() - processStart
        return BatchProcessingResult(
            results = results.values.toList(),
            totalTimeMs = totalTime,
        )
    }

    /**
     * Process a single DEX artifact.
     */
    fun processDex(artifact: Artifact, repairChecksums: Boolean = true): ProcessingResult {
        val start = System.currentTimeMillis()
        val file = artifact.file
        val warnings = mutableListOf<String>()
        val errors = mutableListOf<String>()

        // Step 1: Read file
        val bytes = try {
            file.readBytes()
        } catch (e: Exception) {
            val result = ProcessingResult(
                inputArtifact = artifact,
                status = ProcessingStatus.INVALID_INPUT,
                processingTimeMs = System.currentTimeMillis() - start,
                engine = "PayloadProcessor",
            )
            results[artifact.file.absolutePath] = result
            return result
        }

        // Step 2: Validate DEX structure
        val validationErrors = DexValidator.validate(bytes)
        if (validationErrors.isNotEmpty() && repairChecksums) {
            // Attempt repair
            val repairResult = ChecksumRepair.repairBytes(bytes)
            if (repairResult.isRepaired) {
                warnings.addAll(validationErrors.map { "Repaired: $it" })
                // Write repaired file
                try {
                    file.writeBytes(repairResult.repaired)
                } catch (e: Exception) {
                    errors.add("Failed to write repaired file: ${e.message}")
                }
            } else {
                errors.addAll(repairResult.afterErrors)
            }
        } else {
            errors.addAll(validationErrors)
        }

        // Step 3: Parse DEX metadata
        val metadata = mutableMapOf<String, String>()
        metadata["size"] = bytes.size.toString()
        try {
            val header = com.dpt.unpack.dex.DexParser.parseHeader(bytes)
            metadata["classDefsSize"] = header.classDefsSize.toString()
            metadata["methodIdsSize"] = header.methodIdsSize.toString()
            metadata["stringIdsSize"] = header.stringIdsSize.toString()
        } catch (e: Exception) {
            warnings.add("Could not parse DEX header: ${e.message}")
        }

        // Step 4: Determine status
        val status = when {
            errors.isEmpty() && warnings.isEmpty() -> ProcessingStatus.SUCCESS
            errors.isEmpty() -> ProcessingStatus.PARTIAL
            else -> ProcessingStatus.FAILED
        }

        // Step 5: Create output artifact (normalized)
        val outputArtifact = if (status != ProcessingStatus.FAILED) {
            normalizeDexOutput(artifact, file)
        } else null

        val result = ProcessingResult(
            inputArtifact = artifact,
            status = status,
            outputArtifact = outputArtifact,
            validationErrors = errors,
            warnings = warnings,
            processingTimeMs = System.currentTimeMillis() - start,
            engine = "PayloadProcessor",
            details = metadata,
        )

        results[artifact.file.absolutePath] = result
        return result
    }

    /**
     * Process a non-DEX artifact (pass-through classification).
     */
    fun processNonDex(artifact: Artifact): ProcessingResult {
        val start = System.currentTimeMillis()
        val result = ProcessingResult(
            inputArtifact = artifact,
            status = ProcessingStatus.SUCCESS,
            processingTimeMs = System.currentTimeMillis() - start,
            engine = "PayloadProcessor",
            details = mapOf("type" to artifact.type.name, "source" to artifact.source.name),
        )
        results[artifact.file.absolutePath] = result
        return result
    }

    /**
     * Process multiple DEX files in multi-DEX order.
     *
     * @param dexFiles ordered list of DEX files (classes.dex, classes2.dex, ...)
     * @param repairChecksums whether to attempt repair
     * @return processing results in order
     */
    fun processMultiDex(
        dexFiles: List<File>,
        repairChecksums: Boolean = true,
    ): List<ProcessingResult> {
        val sorted = dexFiles.sortedBy { file ->
            DexDiscovery.dexIndex(file.name) ?: Int.MAX_VALUE
        }
        return sorted.map { file ->
            val artifact = Artifact(
                file = file,
                type = ArtifactType.DEX,
                source = ArtifactSource.UNKNOWN,
                name = file.name,
                size = file.length(),
            )
            processDex(artifact, repairChecksums)
        }
    }

    /**
     * Get the normalized output directory for a job.
     */
    fun getOutputDir(): File {
        val outputDir = workspaceDir.resolve("processed")
        outputDir.mkdirs()
        return outputDir
    }

    /**
     * Normalize DEX output: copy to a predictable location with standard naming.
     */
    private fun normalizeDexOutput(artifact: Artifact, file: File): Artifact {
        val outputDir = getOutputDir()
        val target = outputDir.resolve(file.name)

        if (file.absolutePath != target.absolutePath) {
            try {
                file.copyTo(target, overwrite = true)
            } catch (_: Exception) {}
        }

        return artifact.copy(
            file = target,
            metadata = artifact.metadata + mapOf("normalized" to "true"),
        )
    }

    /**
     * Get all processing results.
     */
    fun getResults(): List<ProcessingResult> = results.values.toList()

    /**
     * Get results for DEX artifacts only.
     */
    fun getDexResults(): List<ProcessingResult> =
        results.values.filter { it.inputArtifact.type == ArtifactType.DEX }

    /**
     * Check if all DEX artifacts were processed successfully.
     */
    fun allDexValid(): Boolean {
        val dexResults = getDexResults()
        return dexResults.isNotEmpty() && dexResults.all { it.status == ProcessingStatus.SUCCESS }
    }

    /**
     * Get summary of multi-DEX processing.
     */
    fun multiDexSummary(): MultiDexSummary {
        val dexResults = getDexResults()
        val ordered = dexResults.sortedBy { result ->
            DexDiscovery.dexIndex(result.inputArtifact.name) ?: Int.MAX_VALUE
        }
        return MultiDexSummary(
            totalDex = ordered.size,
            validDex = ordered.count { it.status == ProcessingStatus.SUCCESS },
            failedDex = ordered.count { it.status == ProcessingStatus.FAILED },
            dexNames = ordered.map { it.inputArtifact.name },
        )
    }
}

data class MultiDexSummary(
    val totalDex: Int,
    val validDex: Int,
    val failedDex: Int,
    val dexNames: List<String>,
) {
    val isComplete: Boolean get() = totalDex > 0 && validDex == totalDex
    val summary: String
        get() = "Multi-DEX: $validDex/$totalDex valid — ${dexNames.joinToString(", ")}"
}
