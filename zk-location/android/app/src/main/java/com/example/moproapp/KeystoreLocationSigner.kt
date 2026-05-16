/*
 * 文件功能：
 * - 封装 Android Keystore/TEE/StrongBox ECDSA P-256 key 的生成、attestation 证书链读取和签名。
 * - 客户端只在 Generate new key and bind 时重新生成并提交 attested key。
 * - 后续签名阶段只用当前 Keystore 私钥签名服务端 nonce 和 public_commitment。
 *
 * 执行流程：
 * 1. createOrReplaceKey 使用服务端 key registration nonce 作为 attestation challenge。
 * 2. 优先尝试 StrongBox attested key，失败后尝试 TEE attested key，最后仅保留开发 fallback。
 * 3. registration 导出 public key 和 certificateChain 给服务端验证。
 * 4. signCommitment 生成规范化 payload 并用私钥签名，服务端使用已绑定公钥验签。
 */
package com.example.moproapp

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

data class LocationKeyRegistration(
    // alias：Android Keystore 中保存该 ECDSA key 的别名。
    val alias: String,
    // publicKeyBase64：leaf certificate 中的 SPKI 公钥，Base64 DER 格式。
    val publicKeyBase64: String,
    // certificateChainBase64：Keystore attestation 证书链，每个证书为 Base64 DER。
    val certificateChainBase64: List<String>,
    // hardwareBacked：Android 本地 KeyInfo 判断私钥是否在安全硬件内。
    val hardwareBacked: Boolean,
    // generationMode：记录 StrongBox/TEE/fallback/已有 key，便于 UI 和实验日志展示。
    val generationMode: String
)

data class LocationCommitmentSignature(
    // alias：执行签名的 Keystore key 别名。
    val alias: String,
    // payload：被签名的规范化文本，绑定 public_commitment 和 server_nonce。
    val payload: String,
    // signatureBase64：SHA256withECDSA 签名结果，Base64 DER ECDSA 签名。
    val signatureBase64: String,
    // publicKeyBase64：当前 leaf public key，仅用于客户端展示/自检，不再随 proof 提交。
    val publicKeyBase64: String,
    // certificateChainBase64：当前证书链，仅用于本地状态展示，不再随 proof 提交。
    val certificateChainBase64: List<String>,
    // verifiedLocally：客户端用 leaf public key 对刚生成签名做一次自检。
    val verifiedLocally: Boolean
)

object KeystoreLocationSigner {
    // ANDROID_KEYSTORE：Android 系统 Keystore provider 名称。
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    // KEY_ALIAS：本项目固定使用的签名 key 别名。
    private const val KEY_ALIAS = "zk_location_tee_ecdsa_p256"
    // SIGNATURE_ALGORITHM：服务端也按此算法验证 ECDSA 签名。
    private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    /** 重新生成 attested key，并返回绑定服务端所需的公钥和证书链。 */
    fun createOrReplaceKey(attestationChallenge: ByteArray): LocationKeyRegistration {
        // keyStore：AndroidKeyStore 实例，用来删除旧 key 和读取新 key。
        val keyStore = loadKeyStore()
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }

        // generationMode：记录实际成功的 key 生成路径。
        val generationMode = generateKey(attestationChallenge)
        return registration(generationMode)
    }

    /** 确保 key 存在；已有 key 不重新生成，仅返回当前注册材料。 */
    fun ensureKey(attestationChallenge: ByteArray): LocationKeyRegistration {
        // keyStore：检查固定 alias 是否已经存在。
        val keyStore = loadKeyStore()
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val generationMode = generateKey(attestationChallenge)
            return registration(generationMode)
        }
        return registration("existing")
    }

    /** 使用 Keystore 私钥签名 public commitment 与服务端 nonce。 */
    fun signCommitment(publicCommitment: String, serverNonce: String): LocationCommitmentSignature {
        ensureKey(serverNonce.toByteArray(StandardCharsets.UTF_8))

        // keyStore：从 AndroidKeyStore 读取不可导出的私钥引用。
        val keyStore = loadKeyStore()
        // privateKey：只可用于签名操作，私钥材料不会导出到应用内存。
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
        // certificates：当前 key 的 attestation 证书链，leaf 证书含公钥。
        val certificates = certificateChain()
        // payload：服务端和客户端共同约定的规范化签名文本。
        val payload = canonicalPayload(publicCommitment, serverNonce)
        // payloadBytes：签名 API 使用的 UTF-8 字节。
        val payloadBytes = payload.toByteArray(StandardCharsets.UTF_8)

        // signer：Android Keystore ECDSA 签名器。
        val signer = Signature.getInstance(SIGNATURE_ALGORITHM)
        signer.initSign(privateKey)
        signer.update(payloadBytes)
        // signature：最终发送给服务端的 DER 编码 ECDSA 签名。
        val signature = signer.sign()

        // verifier：本地自检用验签器，不替代服务端验签。
        val verifier = Signature.getInstance(SIGNATURE_ALGORITHM)
        verifier.initVerify(certificates.first().publicKey)
        verifier.update(payloadBytes)
        // verified：本地签名自检结果，用于 UI 显示。
        val verified = verifier.verify(signature)

        return LocationCommitmentSignature(
            alias = KEY_ALIAS,
            payload = payload,
            signatureBase64 = b64(signature),
            publicKeyBase64 = b64(certificates.first().publicKey.encoded),
            certificateChainBase64 = certificates.map { b64(it.encoded) },
            verifiedLocally = verified
        )
    }

    /** 按 StrongBox -> TEE -> 开发 fallback 顺序尝试生成 key。 */
    private fun generateKey(attestationChallenge: ByteArray): String {
        // failures：收集每种生成路径失败原因，便于最终错误定位。
        val failures = mutableListOf<String>()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generateKeyOnce(attestationChallenge, strongBoxBacked = true, includeAttestation = true)
                return "strongbox_attested"
            } catch (e: Exception) {
                deleteKeyIfPresent()
                failures += "strongbox_attested: ${e.message ?: e.javaClass.simpleName}"
            }
        }

        try {
            generateKeyOnce(attestationChallenge, strongBoxBacked = false, includeAttestation = true)
            return "tee_attested"
        } catch (e: Exception) {
            deleteKeyIfPresent()
            failures += "tee_attested: ${e.message ?: e.javaClass.simpleName}"
        }

        try {
            generateKeyOnce(attestationChallenge, strongBoxBacked = false, includeAttestation = false)
            return "dev_fallback_no_attestation"
        } catch (e: Exception) {
            deleteKeyIfPresent()
            failures += "dev_fallback_no_attestation: ${e.message ?: e.javaClass.simpleName}"
        }

        throw IllegalStateException("Failed to generate Keystore ECDSA key. ${failures.joinToString(" | ")}")
    }

    /** 执行一次具体的 Keystore key 生成。 */
    private fun generateKeyOnce(
        attestationChallenge: ByteArray,
        strongBoxBacked: Boolean,
        includeAttestation: Boolean
    ) {
        // generator：AndroidKeyStore EC keypair generator。
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )

        // builder：定义 key 用途、曲线、摘要算法、attestation challenge 和 StrongBox 需求。
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)

        if (includeAttestation) {
            builder.setAttestationChallenge(attestationChallenge)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && strongBoxBacked) {
            builder.setIsStrongBoxBacked(true)
        }

        generator.initialize(builder.build())
        generator.generateKeyPair()
    }

    /** 将当前 Keystore key 转换为服务端 /keys/register 请求需要的数据。 */
    private fun registration(generationMode: String): LocationKeyRegistration {
        // certificates：服务端验证 attestation chain 和 leaf public key 的材料。
        val certificates = certificateChain()
        return LocationKeyRegistration(
            alias = KEY_ALIAS,
            publicKeyBase64 = b64(certificates.first().publicKey.encoded),
            certificateChainBase64 = certificates.map { b64(it.encoded) },
            hardwareBacked = isHardwareBacked(),
            generationMode = generationMode
        )
    }

    /** 生成服务端也会解析的签名 payload，字段顺序不可随意改变。 */
    private fun canonicalPayload(publicCommitment: String, serverNonce: String): String {
        return "ZK_LOCATION_V1\npublic_commitment=$publicCommitment\nserver_nonce=$serverNonce"
    }

    /** 读取 Android KeyInfo，判断私钥是否位于安全硬件。 */
    private fun isHardwareBacked(): Boolean {
        return try {
            // privateKey：用于查询 KeyInfo 的 Keystore 私钥引用。
            val privateKey = loadKeyStore().getKey(KEY_ALIAS, null) as PrivateKey
            // keyFactory：AndroidKeyStore provider 下的 KeyFactory，可导出 KeyInfo 元数据。
            val keyFactory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            // keyInfo：Android 对该 key 的硬件保护状态描述。
            val keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)
            keyInfo.isInsideSecureHardware
        } catch (_: Exception) {
            false
        }
    }

    /** 读取当前 key 的 X.509 certificateChain。 */
    private fun certificateChain(): List<X509Certificate> {
        return loadKeyStore()
            .getCertificateChain(KEY_ALIAS)
            .orEmpty()
            .map { it as X509Certificate }
    }

    /** 加载 AndroidKeyStore provider。 */
    private fun loadKeyStore(): KeyStore {
        return KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    /** 删除固定 alias 下的旧 key，避免 fallback 失败后留下半成品。 */
    private fun deleteKeyIfPresent() {
        // keyStore：用于检查并删除旧 alias。
        val keyStore = loadKeyStore()
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    /** 将二进制材料编码为无换行 Base64。 */
    private fun b64(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }
}
