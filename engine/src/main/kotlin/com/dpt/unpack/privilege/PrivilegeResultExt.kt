package com.dpt.unpack.privilege

/**
 * Convenience extensions for working with [PrivilegeResult].
 */

/** Get the output string, or throw if the result is a failure. */
fun PrivilegeResult.getOrThrow(): String = when (this) {
    is PrivilegeResult.Success -> output
    is PrivilegeResult.Failure -> throw PrivilegeException(error)
}

/** Get the output string, or return null if the result is a failure. */
fun PrivilegeResult.getOrNull(): String? = when (this) {
    is PrivilegeResult.Success -> output
    is PrivilegeResult.Failure -> null
}

/** Get the output string, or return a default value if the result is a failure. */
fun PrivilegeResult.getOrElse(default: () -> String): String = when (this) {
    is PrivilegeResult.Success -> output
    is PrivilegeResult.Failure -> default()
}

/** Check if the result is a success. */
fun PrivilegeResult.isSuccess(): Boolean = this is PrivilegeResult.Success

/** Check if the result is a failure. */
fun PrivilegeResult.isFailure(): Boolean = this is PrivilegeResult.Failure

/** Get the error if the result is a failure, or null. */
fun PrivilegeResult.errorOrNull(): PrivilegeError? = when (this) {
    is PrivilegeResult.Success -> null
    is PrivilegeResult.Failure -> error
}

/**
 * Exception wrapper for [PrivilegeError] to allow throwing in contexts
 * that expect exceptions (e.g., Kotlin `runCatching`).
 */
class PrivilegeException(val error: PrivilegeError) : Exception(error.humanReadable())
