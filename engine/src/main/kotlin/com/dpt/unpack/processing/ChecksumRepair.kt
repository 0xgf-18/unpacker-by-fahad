package com.dpt.unpack.processing

import com.dpt.unpack.checksum.DexChecksum
import com.dpt.unpack.validate.DexValidator
import java.io.File

/**
 * Handles DEX checksum/signature repair.
 *
 * Uses the existing [DexChecksum.fix] for actual repair operations.
 * Validates before and after repair.
 */
object ChecksumRepair {

    /**
     * Repair a DEX file's checksum and SHA-1 signature.
     *
     * @param file the DEX file to repair (overwrites in place)
     * @return repair result with validation before/after
     */
    fun repairInPlace(file: File): RepairResult {
        val startTime = System.currentTimeMillis()

        if (!file.exists()) {
            return RepairResult(
                file = file,
                repaired = false,
                beforeErrors = listOf("File does not exist"),
                afterErrors = listOf("File does not exist"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        val bytes = try {
            file.readBytes()
        } catch (e: Exception) {
            return RepairResult(
                file = file,
                repaired = false,
                beforeErrors = listOf("Cannot read file: ${e.message}"),
                afterErrors = emptyList(),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        val beforeErrors = DexValidator.validate(bytes)
        if (beforeErrors.isEmpty()) {
            return RepairResult(
                file = file,
                repaired = false,
                beforeErrors = emptyList(),
                afterErrors = emptyList(),
                timeMs = System.currentTimeMillis() - startTime,
                message = "Already valid, no repair needed",
            )
        }

        val repaired = try {
            DexChecksum.fix(bytes)
        } catch (e: Exception) {
            return RepairResult(
                file = file,
                repaired = false,
                beforeErrors = beforeErrors,
                afterErrors = listOf("Repair failed: ${e.message}"),
                timeMs = System.currentTimeMillis() - startTime,
            )
        }

        val afterErrors = DexValidator.validate(repaired)

        if (afterErrors.isEmpty()) {
            file.writeBytes(repaired)
        }

        return RepairResult(
            file = file,
            repaired = afterErrors.isEmpty(),
            beforeErrors = beforeErrors,
            afterErrors = afterErrors,
            timeMs = System.currentTimeMillis() - startTime,
            message = if (afterErrors.isEmpty()) "Repaired successfully" else "Repair attempted but validation still fails",
        )
    }

    /**
     * Repair a DEX byte array without writing to disk.
     *
     * @param dex the raw DEX bytes
     * @return repaired bytes and validation result
     */
    fun repairBytes(dex: ByteArray): ByteArrayRepairResult {
        val beforeErrors = DexValidator.validate(dex)

        if (beforeErrors.isEmpty()) {
            return ByteArrayRepairResult(
                repaired = dex,
                beforeErrors = emptyList(),
                afterErrors = emptyList(),
                message = "Already valid",
            )
        }

        val repaired = try {
            DexChecksum.fix(dex)
        } catch (e: Exception) {
            return ByteArrayRepairResult(
                repaired = dex,
                beforeErrors = beforeErrors,
                afterErrors = listOf("Repair failed: ${e.message}"),
                message = "Repair failed: ${e.message}",
            )
        }

        val afterErrors = DexValidator.validate(repaired)
        return ByteArrayRepairResult(
            repaired = repaired,
            beforeErrors = beforeErrors,
            afterErrors = afterErrors,
            message = if (afterErrors.isEmpty()) "Repaired successfully" else "Partial repair",
        )
    }

    /**
     * Batch repair multiple DEX files.
     */
    fun repairAll(files: List<File>): List<RepairResult> {
        return files.map { repairInPlace(it) }
    }
}

data class RepairResult(
    val file: File,
    val repaired: Boolean,
    val beforeErrors: List<String>,
    val afterErrors: List<String>,
    val timeMs: Long = 0,
    val message: String = "",
) {
    val summary: String
        get() = if (repaired) {
            "[REPAIRED] ${file.name} — ${beforeErrors.size} error(s) fixed"
        } else if (beforeErrors.isEmpty()) {
            "[VALID] ${file.name}"
        } else {
            "[FAILED] ${file.name} — ${afterErrors.size} remaining error(s)"
        }
}

data class ByteArrayRepairResult(
    val repaired: ByteArray,
    val beforeErrors: List<String>,
    val afterErrors: List<String>,
    val message: String = "",
) {
    val isRepaired: Boolean get() = afterErrors.isEmpty() && beforeErrors.isNotEmpty()
}
