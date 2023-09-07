package android.app.sendnoteapp.utils

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import java.security.spec.InvalidKeySpecException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class CryptographicManager {

    companion object {
        private const val KEY_ALIAS = "aesKey"
        private const val IV_SIZE = 12
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun DeleteKey() {
        keyStore.deleteEntry(KEY_ALIAS)
        Log.i("CryptographicManager", "DeleteKey $KEY_ALIAS")

    }

    fun CreateKeyIfNotExist(): SecretKey {
        val aesKey = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        return aesKey?.secretKey ?: return generateKey(true)!!
    }

    private fun generateKey(tryStrongBox: Boolean): SecretKey? {
        try {
            Log.i("CryptographicManager", "generateKey()")
            val secretKey = KeyGenerator.getInstance(ALGORITHM, "AndroidKeyStore").apply {
                init(
                    KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setBlockModes(BLOCK_MODE)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setUserAuthenticationRequired(false)
                        .setRandomizedEncryptionRequired(true).apply {
                            try {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                                    Log.i(
                                        "CryptographicManager",
                                        "attempting to setIsStrongBoxBacked($tryStrongBox)"
                                    )
                                    setIsStrongBoxBacked(tryStrongBox)
                                    Log.i(
                                        "CryptographicManager",
                                        "successfully setIsStrongBoxBacked($tryStrongBox)"
                                    )
                                }
                            } catch (e: Exception) {
                                Log.w("CryptographicManager", "setIsStrongBoxBacked", e)
                            }
                        }
                        .build()
                )
            }.generateKey().also {
                printKeyInfo(it)
            }
            return secretKey
        } catch (e: Exception) {
            Log.w("CryptographicManager", "generateKey", e)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                Log.w("CryptographicManager", "Android version sdk: ${Build.VERSION.SDK_INT}")
                if (e is StrongBoxUnavailableException) {
                    return generateKey(false)
                }
            }
        }

        return null
    }

    fun RetrieveKey(): SecretKey = CreateKeyIfNotExist()

    fun encryptedString(data: String, key: SecretKey): String {
        val encryptCipher = Cipher.getInstance(TRANSFORMATION)
        encryptCipher.init(Cipher.ENCRYPT_MODE, key)

        val encryptedBytes = encryptCipher.doFinal(data.toByteArray())
        Log.i("CryptographicManager", "iv size = ${encryptCipher.iv.size}")
        val ivPrefixedBytes = encryptCipher.iv + encryptedBytes

        return Base64.encodeToString(ivPrefixedBytes, Base64.DEFAULT)
    }

    fun decryptString(encryptedData: String, key: SecretKey): String {
        if (!encryptedData.isNullOrEmpty()) {
            val decodedByteArray = Base64.decode(encryptedData, Base64.DEFAULT)
            val iv = decodedByteArray.slice(0 until IV_SIZE).toByteArray()

            val decryptCipher = Cipher.getInstance(TRANSFORMATION)
            decryptCipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))

            val encryptedBytes =
                decodedByteArray.slice(IV_SIZE until decodedByteArray.size).toByteArray()
            val decryptedBytes = decryptCipher.doFinal(encryptedBytes)

            return decryptedBytes.toString(charset = Charsets.UTF_8)
        } else {
            return ""
        }

    }

    private fun printKeyInfo(key: SecretKey) {
        val keyFactory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        val keyInfo: KeyInfo
        try {
            keyInfo = keyFactory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                val insideSecureHardware = keyInfo.isInsideSecureHardware
                Log.i("CryptographicManager", "isInsideSecureHardware: $insideSecureHardware")
            } else {
                val securityLevel = keyInfo.securityLevel
                when (securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> {
                        Log.i("CryptographicManager", "securityLevel: SECURITY_LEVEL_STRONGBOX")
                    }

                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> {
                        Log.i(
                            "CryptographicManager",
                            "securityLevel: SECURITY_LEVEL_TRUSTED_ENVIRONMENT"
                        )
                    }

                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> {
                        Log.i("CryptographicManager", "securityLevel: SECURITY_LEVEL_SOFTWARE")
                    }

                    KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> {
                        Log.i(
                            "CryptographicManager",
                            "securityLevel: SECURITY_LEVEL_UNKNOWN_SECURE"
                        )
                    }

                    KeyProperties.SECURITY_LEVEL_UNKNOWN -> {
                        Log.i("CryptographicManager", "securityLevel: SECURITY_LEVEL_UNKNOWN")
                    }

                    else -> Log.w("CryptographicManager", "securityLevel: UNKNOWN")
                }
            }
        } catch (e: InvalidKeySpecException) {
            Log.e("CryptographicManager", "keyInfo", e)
        }

    }
}
