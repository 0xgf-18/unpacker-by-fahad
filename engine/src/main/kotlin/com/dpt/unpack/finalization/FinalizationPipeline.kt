package com.dpt.unpack.finalization

import com.dpt.unpack.privilege.PrivilegeManager
import com.dpt.unpack.rebuild.ApkRebuild
import com.dpt.unpack.rebuild.RebuildResult
import java.io.File

/**
 * Orchestrates the full finalization pipeline:
 * REBUILD → SIGN → VERIFY → INSTALL → LAUNCH
 *
 * Each stage is independent and reports its own status.
 * A failure in one stage does not prevent reporting of other stages.
 */
class FinalizationPipeline(
    private val baseDir: File,
    private val privilegeManager: PrivilegeManager,
) {
    /**
     * Execute the full finalization pipeline.
     *
     * @param rebuildResult result from Phase 9 rebuild
     * @param signingConfig signing configuration
     * @param packageName expected package name
     * @param activity optional activity to launch
     * @param skipInstall skip installation (useful for local testing)
     * @param skipLaunch skip launch verification
     * @return aggregated finalization result
     */
    fun execute(
        rebuildResult: RebuildResult,
        signingConfig: SigningConfig,
        packageName: String? = null,
        activity: String? = null,
        skipInstall: Boolean = false,
        skipLaunch: Boolean = false,
    ): FinalizationResult {
        val startTime = System.currentTimeMillis()
        var signingResult: SigningResult? = null
        var sigValidation: SignatureValidationResult? = null
        var installResult: InstallationResult? = null
        var launchResult: LaunchResult? = null

        // Stage 1: Sign (if rebuild produced output)
        val unsignedApk = rebuildResult.outputApk
        if (unsignedApk != null && unsignedApk.exists()) {
            val signedApk = baseDir.resolve("signed").resolve(unsignedApk.name)
            signedApk.parentFile?.mkdirs()

            signingResult = ApkSigner.sign(signingConfig, unsignedApk, signedApk)

            // Stage 2: Verify signature
            if (signingResult.outputApk != null && signingResult.outputApk.exists()) {
                sigValidation = SignatureValidator.validate(signingResult.outputApk)
            }
        }

        // Stage 3: Install (if not skipped and signing succeeded)
        if (!skipInstall && signingResult?.isSuccess == true && signingResult.outputApk != null) {
            val installer = InstallationManager(privilegeManager)
            installResult = installer.install(signingResult.outputApk, packageName)

            // Stage 4: Launch (if not skipped and installation succeeded)
            if (!skipLaunch && installResult.status == InstallStatus.SUCCESS && packageName != null) {
                val launcher = LaunchVerifier(privilegeManager)
                launchResult = launcher.launch(packageName, activity)
            }
        }

        return FinalizationResult(
            rebuildResult = rebuildResult,
            signingResult = signingResult,
            signatureValidation = sigValidation,
            installationResult = installResult,
            launchResult = launchResult,
            totalTimeMs = System.currentTimeMillis() - startTime,
        )
    }

    /**
     * Sign a previously rebuilt APK (convenience for partial pipeline).
     */
    fun signOnly(
        unsignedApk: File,
        signingConfig: SigningConfig,
    ): FinalizationResult {
        val startTime = System.currentTimeMillis()
        val signedApk = baseDir.resolve("signed").resolve(unsignedApk.name)
        signedApk.parentFile?.mkdirs()

        val signingResult = ApkSigner.sign(signingConfig, unsignedApk, signedApk)
        val sigValidation = if (signingResult.outputApk != null && signingResult.outputApk.exists()) {
            SignatureValidator.validate(signingResult.outputApk)
        } else null

        return FinalizationResult(
            signingResult = signingResult,
            signatureValidation = sigValidation,
            totalTimeMs = System.currentTimeMillis() - startTime,
        )
    }

    /**
     * Install a signed APK (convenience for partial pipeline).
     */
    fun installOnly(
        signedApk: File,
        packageName: String,
    ): FinalizationResult {
        val startTime = System.currentTimeMillis()
        val installer = InstallationManager(privilegeManager)
        val installResult = installer.install(signedApk, packageName)

        return FinalizationResult(
            installationResult = installResult,
            totalTimeMs = System.currentTimeMillis() - startTime,
        )
    }
}
