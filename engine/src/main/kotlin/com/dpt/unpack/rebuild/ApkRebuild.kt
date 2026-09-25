package com.dpt.unpack.rebuild

import com.dpt.unpack.processing.PayloadProcessor
import java.io.File

/**
 * Main APK rebuild orchestrator.
 *
 * Takes validated processed artifacts from Phase 8 and produces a structurally
 * valid rebuilt APK. Uses the existing [ApkRebuilder] for core ZIP reconstruction.
 *
 * Pipeline:
 * 1. Prepare workspace (isolate input/output)
 * 2. Stage artifacts (DEX files, manifest)
 * 3. Rebuild APK using existing ApkRebuilder
 * 4. Validate rebuilt APK
 * 5. Return structured result
 */
class ApkRebuild(private val baseDir: File) {

    /**
     * Rebuild an APK from processed artifacts.
     *
     * @param inputApk the original APK
     * @param processedDexes validated DEX files from Phase 8
     * @param restoredManifest restored AndroidManifest.xml bytes
     * @param jobId optional job ID for workspace tracking
     * @return rebuild result with validation
     */
    fun rebuild(
        inputApk: File,
        processedDexes: List<File>,
        restoredManifest: ByteArray,
        jobId: String? = null,
    ): RebuildResult {
        val startTime = System.currentTimeMillis()
        val warnings = mutableListOf<String>()
        val errors = mutableListOf<String>()

        // Step 1: Create workspace
        val workspace = try {
            val ws = RebuildWorkspace.create(baseDir, jobId)
            val prepResult = ws.prepare()
            if (prepResult.isFailure) {
                return RebuildResult(
                    status = RebuildStatus.FAILED,
                    inputApk = inputApk,
                    outputApk = null,
                    validationErrors = listOf("Failed to create workspace: ${prepResult.exceptionOrNull()?.message}"),
                    processingTimeMs = System.currentTimeMillis() - startTime,
                )
            }
            ws
        } catch (e: Exception) {
            return RebuildResult(
                status = RebuildStatus.FAILED,
                inputApk = inputApk,
                outputApk = null,
                validationErrors = listOf("Workspace creation failed: ${e.message}"),
                processingTimeMs = System.currentTimeMillis() - startTime,
            )
        }

        return try {
            // Step 2: Stage input APK
            workspace.stageApk(inputApk).getOrElse { e ->
                return RebuildResult(
                    status = RebuildStatus.INVALID_INPUT,
                    inputApk = inputApk,
                    outputApk = null,
                    validationErrors = listOf("Failed to stage APK: ${e.message}"),
                    processingTimeMs = System.currentTimeMillis() - startTime,
                )
            }

            // Step 3: Stage DEX files
            if (processedDexes.isEmpty()) {
                return RebuildResult(
                    status = RebuildStatus.INVALID_INPUT,
                    inputApk = inputApk,
                    outputApk = null,
                    validationErrors = listOf("No DEX files provided for rebuild"),
                    processingTimeMs = System.currentTimeMillis() - startTime,
                )
            }
            for (dex in processedDexes) {
                workspace.stageDex(dex).getOrElse { e ->
                    errors.add("Failed to stage DEX ${dex.name}: ${e.message}")
                }
            }
            if (errors.isNotEmpty()) {
                return RebuildResult(
                    status = RebuildStatus.FAILED,
                    inputApk = inputApk,
                    outputApk = null,
                    validationErrors = errors,
                    processingTimeMs = System.currentTimeMillis() - startTime,
                )
            }

            // Step 4: Stage manifest
            workspace.stageManifest(restoredManifest).getOrElse { e ->
                return RebuildResult(
                    status = RebuildStatus.FAILED,
                    inputApk = inputApk,
                    outputApk = null,
                    validationErrors = listOf("Failed to stage manifest: ${e.message}"),
                    processingTimeMs = System.currentTimeMillis() - startTime,
                )
            }

            // Step 5: Validate manifest before rebuild
            val manifestResult = ManifestValidator.validate(workspace.manifestFile())
            if (!manifestResult.parseable) {
                return RebuildResult(
                    status = RebuildStatus.INVALID_INPUT,
                    inputApk = inputApk,
                    outputApk = null,
                    manifestStatus = ValidationStatus.FAIL,
                    validationErrors = listOf("Manifest validation failed: ${manifestResult.errors.joinToString("; ")}"),
                    processingTimeMs = System.currentTimeMillis() - startTime,
                )
            }
            manifestResult.warnings.forEach { warnings.add("Manifest: $it") }

            // Step 6: Rebuild APK using existing ApkRebuilder
            val outputApk = workspace.outputApk()
            try {
                ApkRebuilder.rebuild(
                    apk = workspace.inputApk(),
                    patchedDir = workspace.patchedDir,
                    restoredManifest = restoredManifest,
                    out = outputApk,
                )
            } catch (e: Exception) {
                return RebuildResult(
                    status = RebuildStatus.FAILED,
                    inputApk = inputApk,
                    outputApk = null,
                    validationErrors = listOf("ApkRebuilder failed: ${e.message}"),
                    processingTimeMs = System.currentTimeMillis() - startTime,
                )
            }

            if (!outputApk.exists() || outputApk.length() == 0L) {
                return RebuildResult(
                    status = RebuildStatus.FAILED,
                    inputApk = inputApk,
                    outputApk = null,
                    validationErrors = listOf("Rebuilt APK is missing or empty"),
                    processingTimeMs = System.currentTimeMillis() - startTime,
                )
            }

            // Step 7: Validate rebuilt APK
            val apkValidation = ApkValidator.validate(outputApk)
            apkValidation.warnings.forEach { warnings.add(it) }
            apkValidation.errors.forEach { errors.add(it) }

            // Determine overall status
            val status = when {
                errors.isEmpty() && apkValidation.isValid -> RebuildStatus.SUCCESS
                apkValidation.structureValid && apkValidation.dexValid -> RebuildStatus.PARTIAL
                else -> RebuildStatus.FAILED
            }

            // Step 8: Clean temp files
            workspace.cleanTemp()

            RebuildResult(
                status = status,
                inputApk = inputApk,
                outputApk = outputApk,
                outputSize = outputApk.length(),
                dexCount = apkValidation.dexEntries.size,
                nativeLibCount = apkValidation.nativeLibEntries.size,
                manifestStatus = if (apkValidation.manifestValid) {
                    ValidationStatus.PASS
                } else {
                    ValidationStatus.FAIL
                },
                apkStructureStatus = if (apkValidation.structureValid) {
                    ValidationStatus.PASS
                } else {
                    ValidationStatus.FAIL
                },
                dexValidationStatus = if (apkValidation.dexValid) {
                    ValidationStatus.PASS
                } else {
                    ValidationStatus.FAIL
                },
                validationErrors = errors,
                warnings = warnings,
                processingTimeMs = System.currentTimeMillis() - startTime,
                details = mapOf(
                    "jobId" to workspace.jobId,
                    "workspace" to workspace.rootDir.absolutePath,
                    "totalEntries" to apkValidation.entries.size.toString(),
                    "manifestPackage" to (manifestResult.packageName ?: "unknown"),
                ),
            )
        } catch (e: Exception) {
            RebuildResult(
                status = RebuildStatus.FAILED,
                inputApk = inputApk,
                outputApk = null,
                validationErrors = listOf("Unexpected error: ${e.message}"),
                processingTimeMs = System.currentTimeMillis() - startTime,
            )
        }
    }

    /**
     * Rebuild from a PayloadProcessor result.
     *
     * Convenience method that extracts validated DEX files from a completed
     * Phase 8 processing run.
     */
    fun rebuildFromProcessor(
        inputApk: File,
        processor: PayloadProcessor,
        restoredManifest: ByteArray,
        jobId: String? = null,
    ): RebuildResult {
        val dexResults = processor.getDexResults()
            .filter { it.isSuccess || it.isPartial }
            .map { it.outputArtifact?.file ?: it.inputArtifact.file }
            .filter { it.exists() }

        return rebuild(inputApk, dexResults, restoredManifest, jobId)
    }
}
