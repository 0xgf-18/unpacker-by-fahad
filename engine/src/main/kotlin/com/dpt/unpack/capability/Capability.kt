package com.dpt.unpack.capability

/**
 * Models the capabilities required by each unpacking strategy and the
 * capabilities currently available on the host/device.
 */
object Capability {

    enum class Cap {
        STATIC_ANALYSIS,
        DEX_EXTRACTION,
        NATIVE_ANALYSIS,
        REBUILD_SUPPORT,
        SIGNING_SUPPORT,
        APKTOOL,
        ROOT_ACCESS,
        ADB_ACCESS,
        DEVICE_DUMP,
        FRIDA,
        REPAIRIP_JAR,
        SPLIT_APK_SUPPORT,
    }

    data class Status(
        val available: Boolean,
        val reason: String? = null,
        val version: String? = null,
    )

    data class StrategyRequirements(
        val strategy: String,
        val required: Set<Cap>,
        val optional: Set<Cap> = emptySet(),
    )

    val DPT_STRATEGY = StrategyRequirements(
        strategy = "dpt",
        required = setOf(Cap.STATIC_ANALYSIS, Cap.DEX_EXTRACTION, Cap.REBUILD_SUPPORT, Cap.SIGNING_SUPPORT),
    )

    val B2AL_STRATEGY = StrategyRequirements(
        strategy = "b2al",
        required = setOf(Cap.STATIC_ANALYSIS, Cap.DEX_EXTRACTION, Cap.REBUILD_SUPPORT, Cap.SIGNING_SUPPORT),
    )

    val LSPARANOID_STRATEGY = StrategyRequirements(
        strategy = "lsparanoid",
        required = setOf(Cap.STATIC_ANALYSIS, Cap.APKTOOL, Cap.REBUILD_SUPPORT, Cap.SIGNING_SUPPORT),
    )

    val ARK360_STATIC_STRATEGY = StrategyRequirements(
        strategy = "ark_static",
        required = setOf(Cap.STATIC_ANALYSIS, Cap.DEX_EXTRACTION, Cap.REBUILD_SUPPORT, Cap.SIGNING_SUPPORT),
    )

    val ARK360_HYBRID_STRATEGY = StrategyRequirements(
        strategy = "ark_hybrid",
        required = setOf(
            Cap.STATIC_ANALYSIS, Cap.DEX_EXTRACTION, Cap.REBUILD_SUPPORT, Cap.SIGNING_SUPPORT,
            Cap.DEVICE_DUMP, Cap.ROOT_ACCESS,
        ),
    )

    val B2AL_DYNAMIC_STRATEGY = StrategyRequirements(
        strategy = "b2al_dynamic",
        required = setOf(
            Cap.STATIC_ANALYSIS, Cap.REBUILD_SUPPORT, Cap.SIGNING_SUPPORT,
            Cap.DEVICE_DUMP, Cap.ROOT_ACCESS,
        ),
    )

    val PAIRIP_STRATEGY = StrategyRequirements(
        strategy = "pairip",
        required = setOf(Cap.STATIC_ANALYSIS, Cap.REPAIRIP_JAR, Cap.REBUILD_SUPPORT, Cap.SIGNING_SUPPORT),
    )

    val ALL_STRATEGIES = listOf(
        DPT_STRATEGY, B2AL_STRATEGY, B2AL_DYNAMIC_STRATEGY, LSPARANOID_STRATEGY,
        ARK360_STATIC_STRATEGY, ARK360_HYBRID_STRATEGY, PAIRIP_STRATEGY,
    )

    fun checkRequirements(
        reqs: StrategyRequirements,
        available: Map<Cap, Status>,
    ): StrategyCheck {
        val missing = mutableMapOf<Cap, Status>()
        val present = mutableMapOf<Cap, Status>()
        for (cap in reqs.required) {
            val status = available[cap]
            if (status != null && status.available) {
                present[cap] = status
            } else {
                missing[cap] = status ?: Status(false, "not detected")
            }
        }
        val missingOptional = mutableMapOf<Cap, Status>()
        for (cap in reqs.optional) {
            val status = available[cap]
            if (status == null || !status.available) {
                missingOptional[cap] = status ?: Status(false, "not detected")
            }
        }
        return StrategyCheck(
            strategy = reqs.strategy,
            satisfied = missing.isEmpty(),
            missing = missing,
            present = present,
            missingOptional = missingOptional,
        )
    }

    data class StrategyCheck(
        val strategy: String,
        val satisfied: Boolean,
        val missing: Map<Cap, Status>,
        val present: Map<Cap, Status>,
        val missingOptional: Map<Cap, Status>,
    ) {
        fun summary(): String {
            if (satisfied) return "$strategy: READY"
            val missingNames = missing.keys.joinToString { it.name }
            return "$strategy: BLOCKED (missing: $missingNames)"
        }
    }
}
