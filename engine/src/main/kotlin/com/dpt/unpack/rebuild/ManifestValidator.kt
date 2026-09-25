package com.dpt.unpack.rebuild

import com.dpt.unpack.axml.AxmlManifest
import com.dpt.unpack.axml.AxmlStrings
import java.io.File

object ManifestValidator {

    fun validate(manifestFile: File): ManifestValidationResult {
        if (!manifestFile.exists()) {
            return ManifestValidationResult(
                valid = false, parseable = false, hasPackage = false,
                errors = listOf("Manifest file does not exist"),
            )
        }
        if (!manifestFile.canRead()) {
            return ManifestValidationResult(
                valid = false, parseable = false, hasPackage = false,
                errors = listOf("Manifest file is not readable"),
            )
        }
        val bytes = try { manifestFile.readBytes() } catch (e: Exception) {
            return ManifestValidationResult(
                valid = false, parseable = false, hasPackage = false,
                errors = listOf("Cannot read manifest: ${e.message}"),
            )
        }
        return validateBytes(bytes)
    }

    fun validateBytes(bytes: ByteArray): ManifestValidationResult {
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        var parseable = false
        var hasPackage = false
        var packageName: String? = null
        var versionName: String? = null
        var versionCode: String? = null

        if (bytes.size < 8) {
            return ManifestValidationResult(
                valid = false, parseable = false, hasPackage = false,
                errors = listOf("Manifest too small (${bytes.size} bytes)"),
            )
        }

        val isAxml = bytes.size >= 4 &&
            bytes[0] == 0x03.toByte() &&
            bytes[1] == 0x00.toByte() &&
            bytes[2] == 0x08.toByte() &&
            bytes[3] == 0x00.toByte()

        if (!isAxml) {
            val content = String(bytes, Charsets.UTF_8)
            if (content.contains("<?xml") || content.contains("<manifest")) {
                parseable = true
                val pkgMatch = Regex("""package\s*=\s*"([^"]+)"""").find(content)
                if (pkgMatch != null) {
                    hasPackage = true
                    packageName = pkgMatch.groupValues[1]
                }
                val verNameMatch = Regex("""android:versionName\s*=\s*"([^"]+)"""").find(content)
                if (verNameMatch != null) versionName = verNameMatch.groupValues[1]
                val verCodeMatch = Regex("""android:versionCode\s*=\s*"(\d+)"""").find(content)
                if (verCodeMatch != null) versionCode = verCodeMatch.groupValues[1]
                if (!hasPackage) warnings.add("Package attribute not found in plain XML manifest")
            } else {
                errors.add("Not a valid AXML or plain XML manifest")
            }
        } else {
            try {
                val parsed = AxmlManifest.parse(bytes)
                parseable = true
                val manifestTag = AxmlManifest.findTag(parsed, "manifest")
                if (manifestTag != null) {
                    for (attr in manifestTag.attrs) {
                        val name = parsed.strings.getOrNull(attr.nameField.toInt()) ?: continue
                        if (name == "package") {
                            hasPackage = true
                            packageName = attr.valueText.ifBlank { null }
                            break
                        }
                    }
                }
                if (!hasPackage) warnings.add("Package attribute not found in binary AXML manifest")
            } catch (e: Exception) {
                errors.add("Failed to parse binary AXML: ${e.message}")
            }
        }

        return ManifestValidationResult(
            valid = errors.isEmpty() && parseable,
            parseable = parseable,
            hasPackage = hasPackage,
            packageName = packageName,
            versionName = versionName,
            versionCode = versionCode,
            errors = errors,
            warnings = warnings,
        )
    }

    fun validateFromZip(zipBytes: ByteArray, entryName: String = "AndroidManifest.xml"): ManifestValidationResult {
        return try {
            val zip = java.util.zip.ZipInputStream(zipBytes.inputStream())
            var entry: java.util.zip.ZipEntry?
            while (zip.nextEntry.also { entry = it } != null) {
                if (entry?.name == entryName) {
                    return validateBytes(zip.readBytes())
                }
            }
            ManifestValidationResult(
                valid = false, parseable = false, hasPackage = false,
                errors = listOf("Manifest entry '$entryName' not found in ZIP"),
            )
        } catch (e: Exception) {
            ManifestValidationResult(
                valid = false, parseable = false, hasPackage = false,
                errors = listOf("Failed to read manifest from ZIP: ${e.message}"),
            )
        }
    }
}

data class ManifestValidationResult(
    val valid: Boolean,
    val parseable: Boolean,
    val hasPackage: Boolean,
    val packageName: String? = null,
    val versionName: String? = null,
    val versionCode: String? = null,
    val errors: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
) {
    val summary: String
        get() = buildString {
            append("Manifest: ${if (valid) "VALID" else "INVALID"}")
            packageName?.let { append(" | Package: $it") }
            versionName?.let { append(" | Version: $it") }
            versionCode?.let { append(" | Code: $it") }
            if (errors.isNotEmpty()) append(" | ${errors.size} error(s)")
            if (warnings.isNotEmpty()) append(" | ${warnings.size} warning(s)")
        }
}
