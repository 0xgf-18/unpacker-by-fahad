package com.dpt.unpack.finalization

import java.io.File

/**
 * Configuration for APK signing.
 *
 * Uses environment variables and file-based configuration.
 * Never hardcodes credentials in source code.
 */
data class SigningConfig(
    /** Path to the keystore file. */
    val keystorePath: File,
    /** Keystore password. Read from environment if not set. */
    val storePassword: String = System.getenv("DPT_STORE_PASS") ?: "",
    /** Key password. Read from environment if not set. */
    val keyPassword: String = System.getenv("DPT_KEY_PASS") ?: "",
    /** Key alias in the keystore. */
    val keyAlias: String = System.getenv("DPT_KEY_ALIAS") ?: "dpt-dumper",
    /** Path to Android build-tools directory. */
    val buildToolsDir: File? = findBuildTools(),
) {
    val isValid: Boolean
        get() = keystorePath.exists() &&
            storePassword.isNotBlank() &&
            keyPassword.isNotBlank() &&
            keyAlias.isNotBlank()

    val isBuildToolsAvailable: Boolean
        get() = buildToolsDir != null && buildToolsDir.isDirectory

    fun summary(): String = buildString {
        append("Keystore: ${if (keystorePath.exists()) "OK" else "MISSING"}")
        append(" | Build-tools: ${if (isBuildToolsAvailable) "OK" else "MISSING"}")
        append(" | Alias: $keyAlias")
    }

    companion object {
        /**
         * Create a configuration using the throwaway keystore.
         * Credentials are read from environment variables.
         */
        fun throwaway(outputDir: File): SigningConfig {
            val ks = outputDir.resolve("dpt-dumper.jks")
            return SigningConfig(
                keystorePath = ks,
                storePassword = System.getenv("DPT_STORE_PASS") ?: "dptunpack",
                keyPassword = System.getenv("DPT_KEY_PASS") ?: "dptunpack",
                keyAlias = System.getenv("DPT_KEY_ALIAS") ?: "dpt-dumper",
            )
        }

        /**
         * Create from explicit parameters.
         */
        fun of(
            keystorePath: File,
            storePassword: String,
            keyPassword: String,
            keyAlias: String = "dpt-dumper",
        ) = SigningConfig(keystorePath, storePassword, keyPassword, keyAlias)

        private fun findBuildTools(): File? {
            System.getenv("DPT_BUILD_TOOLS")?.takeIf { it.isNotBlank() }?.let { p ->
                val f = File(p)
                if (f.isDirectory && f.resolve("lib/apksigner.jar").exists()) return f
            }
            val androidHome = System.getenv("ANDROID_HOME") ?: return null
            val btDir = File(androidHome, "build-tools")
            if (!btDir.isDirectory) return null
            return btDir.listFiles()
                ?.filter { it.isDirectory }
                ?.sortedByDescending { it.name }
                ?.firstOrNull { it.resolve("lib/apksigner.jar").exists() }
        }
    }
}
