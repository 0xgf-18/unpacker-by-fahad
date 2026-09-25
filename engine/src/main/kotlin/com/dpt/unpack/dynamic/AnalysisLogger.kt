package com.dpt.unpack.dynamic

import java.time.Instant

/**
 * Structured logger for dynamic analysis sessions.
 *
 * Each log entry has a timestamp, level, tag (component name), and message.
 * Logs are retained in memory for the session duration and can be retrieved
 * for UI display or reporting.
 */
class AnalysisLogger(private val sessionTag: String = "DynamicAnalysis") {

    private val entries = mutableListOf<LogEntry>()
    private val listeners = mutableListOf<(LogEntry) -> Unit>()

    /** Minimum level to emit. Set to [LogLevel.DEBUG] for verbose output. */
    var minLevel: LogLevel = LogLevel.INFO

    fun addListener(listener: (LogEntry) -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: (LogEntry) -> Unit) {
        listeners.remove(listener)
    }

    fun d(tag: String, message: String) = log(LogLevel.DEBUG, tag, message)
    fun i(tag: String, message: String) = log(LogLevel.INFO, tag, message)
    fun w(tag: String, message: String) = log(LogLevel.WARNING, tag, message)
    fun e(tag: String, message: String, error: Throwable? = null) = log(LogLevel.ERROR, tag, message, error)

    fun phase(tag: String, phase: AnalysisPhase, message: String = "") {
        val msg = if (message.isNotBlank()) "[${phase.name}] $message" else "[${phase.name}]"
        i(tag, msg)
    }

    fun result(tag: String, success: Boolean, message: String) {
        val prefix = if (success) "[OK]" else "[FAIL]"
        i(tag, "$prefix $message")
    }

    private fun log(level: LogLevel, tag: String, message: String, error: Throwable? = null) {
        if (level.ordinal < minLevel.ordinal) return
        val entry = LogEntry(
            timestamp = Instant.now(),
            level = level,
            tag = "$sessionTag/$tag",
            message = message,
            error = error,
        )
        synchronized(entries) { entries.add(entry) }
        for (listener in listeners) {
            try { listener(entry) } catch (_: Exception) {}
        }
    }

    fun getEntries(): List<LogEntry> = synchronized(entries) { entries.toList() }

    fun getEntries(level: LogLevel): List<LogEntry> =
        synchronized(entries) { entries.filter { it.level == level } }

    fun clear() = synchronized(entries) { entries.clear() }
}

enum class LogLevel { DEBUG, INFO, WARNING, ERROR }

data class LogEntry(
    val timestamp: Instant,
    val level: LogLevel,
    val tag: String,
    val message: String,
    val error: Throwable? = null,
) {
    fun format(): String {
        val ts = timestamp.toString().take(23)
        val errSuffix = error?.let { " | ${it.message ?: it::class.simpleName}" } ?: ""
        return "[$ts] ${level.name.first()}/$tag: $message$errSuffix"
    }
}
