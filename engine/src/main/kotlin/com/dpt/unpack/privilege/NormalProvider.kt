package com.dpt.unpack.privilege

/**
 * Non-privileged fallback provider. Runs commands in the app's own process
 * sandbox without root or Shizuku access.
 *
 * Capabilities:
 * - Execute commands in the app's own shell context (limited)
 * - Basic file operations within the app's sandbox
 *
 * Limitations:
 * - Cannot install APKs
 * - Cannot access other apps' data
 * - Cannot pull files from arbitrary device paths
 * - Cannot execute su or ADB commands
 */
class NormalProvider : PrivilegeProvider {

    override val level: PrivilegeLevel = PrivilegeLevel.NORMAL
    override val displayName: String = "Normal (no root)"

    override fun isAvailable(): Boolean = true

    override fun exec(command: String, timeoutMs: Long): PrivilegeResult {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))
            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            val exited = process.waitFor()
            if (exited == 0) {
                PrivilegeResult.Success(stdout.trim())
            } else {
                PrivilegeResult.Failure(
                    PrivilegeError.ExecutionFailed(command, exited, stderr.trim())
                )
            }
        } catch (e: Exception) {
            PrivilegeResult.Failure(
                PrivilegeError.ProviderError("Normal", e.message ?: "unknown error")
            )
        }
    }

    override fun installApk(apkPath: String): PrivilegeResult {
        return PrivilegeResult.Failure(
            PrivilegeError.NotSupported("installApk", level)
        )
    }

    override fun launchApp(packageName: String, activity: String?): PrivilegeResult {
        return PrivilegeResult.Failure(
            PrivilegeError.NotSupported("launchApp", level)
        )
    }

    override fun pullFile(devicePath: String, localPath: String): PrivilegeResult {
        return PrivilegeResult.Failure(
            PrivilegeError.NotSupported("pullFile", level)
        )
    }

    override fun pushFile(localPath: String, devicePath: String): PrivilegeResult {
        return PrivilegeResult.Failure(
            PrivilegeError.NotSupported("pushFile", level)
        )
    }

    override fun readFile(devicePath: String): PrivilegeResult {
        return PrivilegeResult.Failure(
            PrivilegeError.NotSupported("readFile", level)
        )
    }

    override fun listDir(devicePath: String): PrivilegeResult {
        return PrivilegeResult.Failure(
            PrivilegeError.NotSupported("listDir", level)
        )
    }
}
