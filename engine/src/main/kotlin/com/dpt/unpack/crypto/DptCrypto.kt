package com.dpt.unpack.crypto

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Mirror of the DPT-Shell crypto scheme (dpt/CryptoUtils.java + shell dpt_crypto.cpp).
 */
object DptCrypto {

    /** RC4 stream cipher, encrypt == decrypt. */
    fun rc4(key: ByteArray, data: ByteArray): ByteArray {
        val s = ByteArray(256) { it.toByte() }
        var j = 0
        for (i in 0 until 256) {
            j = (j + s[i].toInt() + key[i % key.size].toInt()) and 0xFF
            val t = s[i]; s[i] = s[j]; s[j] = t
        }
        val out = data.copyOf()
        var i = 0
        j = 0
        for (k in out.indices) {
            i = (i + 1) and 0xFF
            j = (j + s[i].toInt()) and 0xFF
            val t = s[i]; s[i] = s[j]; s[j] = t
            out[k] = (out[k].toInt() xor s[(s[i].toInt() + s[j].toInt()) and 0xFF].toInt()).toByte()
        }
        return out
    }

    fun hmacSha256(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(msg)
    }

    fun aesCbcDecrypt(key256: ByteArray, iv: ByteArray, data: ByteArray): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key256, "AES"), IvParameterSpec(iv))
            cipher.doFinal(data)
        } catch (e: Exception) {
            null
        }
    }

    /** aesKey = HMAC-SHA256(soKey, packageName + "_" + buildKey)  (32 bytes). */
    fun deriveInsnsKey(soKey: ByteArray, packageName: String, buildKey: String): ByteArray =
        hmacSha256(soKey, (packageName + "_" + buildKey).toByteArray(Charsets.UTF_8))

    /** IV for the shell-config AES-CBC: soKey with slots 3 -> 0x2f and 9 -> 0x76. */
    fun generateIv(soKey: ByteArray): ByteArray {
        if (soKey.size < 10) return soKey.copyOf()
        return soKey.copyOf().also {
            it[3] = 0x2f
            it[9] = 0x76
        }
    }

    /** RC4 key for a code item: aesKey followed by little-endian u32 methodIdx. */
    fun buildInsnsRc4Key(aesKey: ByteArray, methodIdx: Int): ByteArray {
        val out = ByteArray(aesKey.size + 4)
        aesKey.copyInto(out)
        out[aesKey.size] = methodIdx.toByte()
        out[aesKey.size + 1] = (methodIdx ushr 8).toByte()
        out[aesKey.size + 2] = (methodIdx ushr 16).toByte()
        out[aesKey.size + 3] = (methodIdx ushr 24).toByte()
        return out
    }
}