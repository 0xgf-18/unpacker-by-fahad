package com.dpt.unpack.capability

import com.dpt.unpack.privilege.PrivilegeManager
import com.dpt.unpack.privilege.PrivilegeProvider

/**
 * Probes and reports device-level capabilities (root, ADB, device dump).
 */
object DeviceCapabilityProvider {

    private var cachedCapabilities: Map<Capability.Cap, Capability.Status>? = null

    fun probe(privilegeManager: PrivilegeManager): Map<Capability.Cap, Capability.Status> {
        val caps = mutableMapOf<Capability.Cap, Capability.Status>()

        val provider = privilegeManager.select(com.dpt.unpack.privilege.PrivilegeLevel.ROOT)
        val hasRoot = provider != null && provider.level == com.dpt.unpack.privilege.PrivilegeLevel.ROOT
        val hasShizuku = provider != null && provider.level == com.dpt.unpack.privilege.PrivilegeLevel.SHIZUKU

        caps[Capability.Cap.ROOT_ACCESS] = if (hasRoot) {
            Capability.Status(true, provider?.displayName)
        } else {
            Capability.Status(false, "No root access available")
        }

        caps[Capability.Cap.ADB_ACCESS] = Capability.Status(
            DependencyManager.checkAdb().available,
            DependencyManager.checkAdb().reason,
        )

        caps[Capability.Cap.DEVICE_DUMP] = if (hasRoot || hasShizuku) {
            Capability.Status(true, "Device accessible via ${provider?.displayName}")
        } else {
            Capability.Status(false, "Requires root or Shizuku for device dump")
        }

        caps[Capability.Cap.FRIDA] = Capability.Status(
            DependencyManager.checkFrida().available,
            DependencyManager.checkFrida().reason,
        )

        caps[Capability.Cap.STATIC_ANALYSIS] = Capability.Status(true, "Always available")
        caps[Capability.Cap.DEX_EXTRACTION] = Capability.Status(true, "Always available")
        caps[Capability.Cap.NATIVE_ANALYSIS] = Capability.Status(true, "ELF parsing available")
        caps[Capability.Cap.REBUILD_SUPPORT] = Capability.Status(true, "ZIP rebuild available")
        caps[Capability.Cap.SIGNING_SUPPORT] = Capability.Status(true, "APK signing available")
        caps[Capability.Cap.SPLIT_APK_SUPPORT] = Capability.Status(false, "Split APK handling not yet implemented")

        cachedCapabilities = caps
        return caps
    }

    fun getCached(): Map<Capability.Cap, Capability.Status> =
        cachedCapabilities ?: probe(PrivilegeManager())

    fun findBestStrategy(
        detectedStrategies: List<String>,
        available: Map<Capability.Cap, Capability.Status>,
    ): String? {
        for (strategy in detectedStrategies) {
            val reqs = Capability.ALL_STRATEGIES.find { it.strategy == strategy } ?: continue
            val check = Capability.checkRequirements(reqs, available)
            if (check.satisfied) return strategy
        }
        return null
    }

    fun explainBlockage(strategy: String, available: Map<Capability.Cap, Capability.Status>): String {
        val reqs = Capability.ALL_STRATEGIES.find { it.strategy == strategy }
            ?: return "Unknown strategy: $strategy"
        val check = Capability.checkRequirements(reqs, available)
        if (check.satisfied) return "$strategy: READY"
        val missing = check.missing.entries.joinToString("\n") { (cap, status) ->
            "  ${cap.name}: ${status.reason ?: "not available"}"
        }
        return "$strategy: BLOCKED\nMissing capabilities:\n$missing"
    }
}
