package com.dpt.unpack.dynamic

import com.dpt.unpack.privilege.PrivilegeManager
import com.dpt.unpack.privilege.PrivilegeProvider
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference

/**
 * Orchestrates the full dynamic analysis lifecycle.
 *
 * This is the main entry point for runtime analysis. It coordinates:
 * - Workspace preparation
 * - Privilege detection
 * - APK installation
 * - Application launch
 * - Runtime monitoring
 * - Payload collection
 * - Payload validation
 * - Cleanup
 *
 * Usage:
 * ```
 * val controller = DynamicAnalysisController(baseDir, privilegeManager)
 * controller.configure(apkFile, "com.target.app")
 * controller.start()
 * // ... or cancel/stop
 * controller.stop()
 * ```
 *
 * All state transitions are thread-safe.
 */
class DynamicAnalysisController(
    private val baseDir: File,
    private val privilegeManager: PrivilegeManager,
) {
    private val tag = "DynController"
    private val logger = AnalysisLogger(tag)
    private val state = AtomicReference(AnalysisState())
    private val listeners = CopyOnWriteArrayList<(AnalysisState) -> Unit>()

    private var workspace: AnalysisWorkspace? = null
    private var provider: PrivilegeProvider? = null
    private var targetManager: TargetApplicationManager? = null
    private var monitor: RuntimeMonitor? = null
    private var collectors: MutableList<PayloadCollector> = mutableListOf()
    private var validator: PayloadValidator = DefaultPayloadValidator()

    private var targetApk: File? = null
    private var targetPackage: String? = null
    private var targetActivity: String? = null
    private var analysisJob: Thread? = null
    @Volatile private var cancelled = false

    fun addListener(listener: (AnalysisState) -> Unit) { listeners.add(listener) }
    fun removeListener(listener: (AnalysisState) -> Unit) { listeners.remove(listener) }
    fun getLogger(): AnalysisLogger = logger
    fun getState(): AnalysisState = state.get()

    /**
     * Configure the analysis target. Must be called before [start].
     *
     * @param apk the APK file to analyze
     * @param packageName the package name of the target app
     * @param activity optional explicit activity to launch
     * @param collectorFactory optional factory to create protector-specific collectors
     */
    fun configure(
        apk: File,
        packageName: String,
        activity: String? = null,
        collectorFactory: ((PrivilegeProvider) -> List<PayloadCollector>)? = null,
    ) {
        require(state.get().phase == AnalysisPhase.IDLE || state.get().isTerminal) {
            "Cannot configure while analysis is active (phase: ${state.get().phase})"
        }
        require(apk.exists()) { "APK does not exist: ${apk.absolutePath}" }

        targetApk = apk
        targetPackage = packageName
        targetActivity = activity

        // Reset to configured state
        state.set(AnalysisState(phase = AnalysisPhase.IDLE, metadata = mapOf(
            "apk" to apk.absolutePath,
            "package" to packageName,
        )))
        emitState()

        // Prepare collectors
        collectors.clear()
        collectors.add(FdPayloadCollector())
        collectorFactory?.let { factory ->
            val priv = selectPrivilegeProvider()
            if (priv != null) {
                collectors.addAll(factory(priv))
            }
        }
    }

    /**
     * Start the dynamic analysis. Runs asynchronously.
     */
    fun start() {
        val currentState = state.get()
        require(!currentState.isActive) { "Analysis already active (phase: ${currentState.phase})" }
        require(targetApk != null && targetPackage != null) { "Call configure() first" }

        cancelled = false
        analysisJob = Thread({ runAnalysis() }, "dpt-dynamic-analysis").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Stop the analysis gracefully. Collects whatever is available.
     */
    fun stop() {
        if (!state.get().isActive) return
        cancelled = true
        updateState(AnalysisPhase.STOPPING, "Stopping analysis...")
        monitor?.stop()
        analysisJob?.join(5000)
    }

    /**
     * Cancel the analysis and clean up without collecting results.
     */
    fun cancel() {
        cancelled = true
        monitor?.stop()
        analysisJob?.join(3000)
        cleanup()
        updateState(AnalysisPhase.CANCELLED, "Analysis cancelled")
    }

    /**
     * Run the full analysis pipeline. Called from the analysis thread.
     */
    private fun runAnalysis() {
        try {
            // Phase: PREPARING
            updateState(AnalysisPhase.PREPARING, "Preparing workspace and privileges")
            val ws = prepareWorkspace()
            val priv = selectPrivilegeProvider()
                ?: throw AnalysisError.PrivilegeUnavailable("No suitable privilege provider found")
            provider = priv
            targetManager = DefaultTargetApplicationManager(priv)
            monitor = DefaultRuntimeMonitor(priv)

            // Phase: INSTALLING
            updateState(AnalysisPhase.INSTALLING, "Installing APK", progress = 0.1f)
            val installResult = targetManager!!.install(targetApk!!)
            if (installResult.isFailure) {
                throw AnalysisError.InstallationFailed(
                    targetPackage!!,
                    installResult.exceptionOrNull()?.message ?: "unknown"
                )
            }
            logger.i(tag, "APK installed: ${targetPackage}")

            // Phase: LAUNCHING
            updateState(AnalysisPhase.LAUNCHING, "Launching application", progress = 0.2f)
            val launchResult = targetManager!!.launch(targetPackage!!, targetActivity)
            if (launchResult.isFailure) {
                throw AnalysisError.LaunchFailed(
                    targetPackage!!,
                    launchResult.exceptionOrNull()?.message ?: "unknown"
                )
            }
            logger.i(tag, "App launched: ${targetPackage}")

            // Phase: MONITORING
            updateState(AnalysisPhase.MONITORING, "Monitoring runtime", progress = 0.3f)
            monitor!!.start(targetPackage!!, ws)

            // Wait for the app to initialize (configurable delay)
            val waitMs = System.getenv("DPT_MONITOR_WAIT_MS")?.toLongOrNull() ?: 5000L
            logger.i(tag, "Waiting ${waitMs}ms for app initialization")
            Thread.sleep(waitMs)
            if (cancelled) { cancel(); return }

            // Check if app is still running
            if (!targetManager!!.isRunning(targetPackage!!)) {
                logger.w(tag, "Target app crashed or exited during monitoring")
            }

            // Phase: COLLECTING
            updateState(AnalysisPhase.COLLECTING, "Collecting payloads", progress = 0.6f)
            val snapshot = monitor!!.snapshot(targetPackage!!)
            val allPayloads = mutableListOf<CollectedPayload>()
            for (collector in collectors) {
                if (cancelled) { cancel(); return }
                if (!collector.canOperateWith(priv.level)) {
                    logger.w(tag, "Skipping ${collector.name} — requires different privilege level")
                    continue
                }
                logger.i(tag, "Running collector: ${collector.name}")
                try {
                    val payloads = collector.collect(targetPackage!!, snapshot.pid, ws, logger)
                    allPayloads.addAll(payloads)
                    logger.result(tag, true, "${collector.name} collected ${payloads.size} payload(s)")
                } catch (e: Exception) {
                    logger.e(tag, "${collector.name} failed", e)
                }
            }

            // Phase: VALIDATING
            updateState(AnalysisPhase.VALIDATING, "Validating payloads", progress = 0.8f)
            val report = validator.validateAll(allPayloads, ws)
            logger.i(tag, report.summary)

            // Phase: COMPLETE
            updateState(AnalysisPhase.COMPLETE, report.summary, progress = 1.0f, metadata = mapOf(
                "total_payloads" to report.totalPayloads.toString(),
                "valid_payloads" to report.validPayloads.toString(),
                "dex_artifacts" to report.dexArtifacts.toString(),
                "native_artifacts" to report.nativeArtifacts.toString(),
                "confidence" to report.overallConfidence.toString(),
            ))

        } catch (e: AnalysisError) {
            logger.e(tag, e.humanReadable())
            updateState(AnalysisPhase.ERROR, e.humanReadable(), error = e)
        } catch (e: Exception) {
            val err = AnalysisError.Internal(e.message ?: "unknown", e)
            logger.e(tag, err.humanReadable(), e)
            updateState(AnalysisPhase.ERROR, err.humanReadable(), error = err)
        } finally {
            monitor?.stop()
            saveLogs()
        }
    }

    private fun prepareWorkspace(): AnalysisWorkspace {
        val ws = AnalysisWorkspace.create(baseDir)
        val prepared = ws.prepare()
        if (prepared.isFailure) {
            throw AnalysisError.WorkspaceFailed(prepared.exceptionOrNull()?.message ?: "mkdir failed")
        }
        targetApk?.let { ws.stageApk(it) }
        workspace = ws
        logger.i(tag, "Workspace ready: ${ws.rootDir.absolutePath}")
        return ws
    }

    private fun selectPrivilegeProvider(): PrivilegeProvider? {
        val levels = listOf(
            com.dpt.unpack.privilege.PrivilegeLevel.ROOT,
            com.dpt.unpack.privilege.PrivilegeLevel.SHIZUKU,
            com.dpt.unpack.privilege.PrivilegeLevel.NORMAL,
        )
        for (level in levels) {
            val p = privilegeManager.select(level)
            if (p != null && p.isAvailable()) {
                logger.i(tag, "Selected privilege provider: ${p.displayName}")
                return p
            }
        }
        return null
    }

    private fun updateState(
        phase: AnalysisPhase,
        message: String = "",
        progress: Float = state.get().progress,
        error: AnalysisError? = null,
        metadata: Map<String, String> = emptyMap(),
    ) {
        val current = state.get()
        state.set(current.copy(
            phase = phase,
            message = message,
            progress = progress,
            error = error,
            metadata = current.metadata + metadata,
        ))
        emitState()
    }

    private fun emitState() {
        val s = state.get()
        for (listener in listeners) {
            try { listener(s) } catch (_: Exception) {}
        }
    }

    private fun saveLogs() {
        val ws = workspace ?: return
        try {
            val logFile = ws.logsDir.resolve("analysis.log")
            logFile.writeText(logger.getEntries().joinToString("\n") { it.format() })
        } catch (_: Exception) {}
    }

    private fun cleanup() {
        targetPackage?.let { pkg ->
            try { targetManager?.forceStop(pkg) } catch (_: Exception) {}
            try { targetManager?.uninstall(pkg) } catch (_: Exception) {}
        }
        monitor?.stop()
        workspace?.cleanWork()
    }
}
