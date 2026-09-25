package com.dpt.unpack.privilege

/**
 * Privilege levels available on an Android device.
 */
enum class PrivilegeLevel {
    /** Full root access (su binary available and granted). */
    ROOT,
    /** Shizuku IPC access (ADB or root Shizuku service running). */
    SHIZUKU,
    /** No elevated privileges; app runs with standard sandbox permissions. */
    NORMAL,
}

/**
 * Result of a privileged operation.
 */
sealed class PrivilegeResult {
    /** Operation succeeded. */
    data class Success(val output: String) : PrivilegeResult()

    /** Operation failed with a structured error. */
    data class Failure(val error: PrivilegeError) : PrivilegeResult()
}

/**
 * Structured errors for privilege-related failures.
 */
sealed class PrivilegeError {
    /** Required privilege level is not available. */
    data class Unavailable(val required: PrivilegeLevel, val available: PrivilegeLevel, val reason: String) : PrivilegeError()

    /** Command execution failed. */
    data class ExecutionFailed(val command: String, val exitCode: Int, val stderr: String) : PrivilegeError()

    /** Provider-specific error. */
    data class ProviderError(val provider: String, val message: String) : PrivilegeError()

    /** Operation not supported by this provider. */
    data class NotSupported(val operation: String, val provider: PrivilegeLevel) : PrivilegeError()

    fun humanReadable(): String = when (this) {
        is Unavailable -> "Requires $required but only $available is available: $reason"
        is ExecutionFailed -> "Command failed (exit $exitCode): $command\n$stderr"
        is ProviderError -> "$provider error: $message"
        is NotSupported -> "Operation '$operation' is not supported by $provider"
    }
}
