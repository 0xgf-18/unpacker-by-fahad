package com.dpt.unpack.privilege

/**
 * Central manager for privilege detection and provider selection.
 *
 * Usage:
 * ```
 * val manager = PrivilegeManager()
 * val provider = manager.select(PrivilegeLevel.ROOT)  // or any level
 * if (provider != null) {
 *     provider.exec("id")
 * }
 * ```
 *
 * The manager probes available providers once and caches results.
 * Call [reset] to re-probe (e.g., after Shizuku permission changes).
 */
class PrivilegeManager {

    private val providers = mutableMapOf<PrivilegeLevel, PrivilegeProvider>()
    private val availabilityCache = mutableMapOf<PrivilegeLevel, Boolean>()

    /**
     * Register a provider instance. Called by the Android app to provide
     * platform-specific implementations (e.g., Shizuku with a binder).
     */
    fun register(provider: PrivilegeProvider) {
        providers[provider.level] = provider
    }

    /**
     * Detect which providers are available.
     * Probes each registered provider's [PrivilegeProvider.isAvailable].
     *
     * @return map of privilege levels to availability
     */
    fun detect(): Map<PrivilegeLevel, Boolean> {
        if (availabilityCache.isNotEmpty()) return availabilityCache.toMap()
        for ((level, provider) in providers) {
            availabilityCache[level] = try {
                provider.isAvailable()
            } catch (_: Exception) {
                false
            }
        }
        return availabilityCache.toMap()
    }

    /**
     * Select the best available provider at or above the requested level.
     *
     * Priority: ROOT > SHIZUKU > NORMAL
     *
     * @param requested the minimum privilege level required
     * @return the best available provider, or null if none meets the requirement
     */
    fun select(requested: PrivilegeLevel): PrivilegeProvider? {
        detect()
        val ordered = listOf(PrivilegeLevel.ROOT, PrivilegeLevel.SHIZUKU, PrivilegeLevel.NORMAL)
        val startIdx = ordered.indexOf(requested).coerceAtLeast(0)
        for (i in startIdx until ordered.size) {
            val level = ordered[i]
            if (availabilityCache[level] == true) {
                return providers[level]
            }
        }
        return null
    }

    /**
     * Get a specific provider by level, regardless of availability.
     */
    fun get(level: PrivilegeLevel): PrivilegeProvider? = providers[level]

    /**
     * Get all registered providers.
     */
    fun all(): Map<PrivilegeLevel, PrivilegeProvider> = providers.toMap()

    /**
     * Get a summary of provider availability for UI display.
     */
    fun summary(): List<ProviderSummary> {
        detect()
        return PrivilegeLevel.entries.map { level ->
            val provider = providers[level]
            ProviderSummary(
                level = level,
                displayName = provider?.displayName ?: level.name,
                available = availabilityCache[level] ?: false,
                registered = provider != null,
            )
        }
    }

    /**
     * Re-detect availability (e.g., after user grants Shizuku permission).
     */
    fun reset() {
        availabilityCache.clear()
    }

    /**
     * Close all providers and release resources.
     */
    fun close() {
        for (provider in providers.values) {
            try { provider.close() } catch (_: Exception) {}
        }
        providers.clear()
        availabilityCache.clear()
    }

    data class ProviderSummary(
        val level: PrivilegeLevel,
        val displayName: String,
        val available: Boolean,
        val registered: Boolean,
    )
}
