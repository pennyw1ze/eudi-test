package dev.eudi.testbed

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.KeyAttestationJWT
import eu.europa.ec.eudi.openid4vci.SignFunction
import eu.europa.ec.eudi.openid4vci.SignOperation
import eu.europa.ec.eudi.openid4vci.Signer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.time.Instant
import java.util.Date

/** ES256 everywhere: it is what the reference issuer and verifier both accept. */
private const val JAVA_SIGNING_ALGORITHM = "SHA256withECDSA"

/**
 * A [Signer] over an EC private key.
 *
 * The library transcodes the DER signature that JCA produces into the concatenated
 * form JWS requires, so this returns `Signature.sign()` output untouched.
 */
class EcSigner<PUB>(
    private val key: ECKey,
    private val publicMaterial: PUB,
) : Signer<PUB> {

    override val javaAlgorithm: String = JAVA_SIGNING_ALGORITHM

    override suspend fun acquire(): SignOperation<PUB> {
        val privateKey = key.toECPrivateKey() as ECPrivateKey
        val sign = SignFunction { input ->
            withContext(Dispatchers.IO) {
                Signature.getInstance(JAVA_SIGNING_ALGORITHM).run {
                    initSign(privateKey)
                    update(input)
                    sign()
                }
            }
        }
        return SignOperation(sign, publicMaterial)
    }

    override suspend fun release(signOperation: SignOperation<PUB>?) = Unit
}

/**
 * One wallet unit's key material.
 *
 * [deviceKey] is the key a credential gets bound to and that later signs key-binding
 * JWTs when presenting. [attestationKey] stands in for the key a real wallet
 * provider would use to attest that the device key lives in secure hardware.
 *
 * Every unit gets its own set. That is what makes two units genuinely distinct holders
 * rather than two labels over one identity: a credential bound to one unit's device key
 * cannot be presented by the other, and the trace shows exactly why.
 */
class WalletKeys(
    val unitId: String = "default",
    private val crypto: CryptoSink? = null,
) {

    val deviceKey: ECKey = generateKey("device")
    private val attestationKey: ECKey = generateKey("wallet-provider")

    /** Binds access tokens to this wallet via DPoP; the sample realm requires it. */
    val dpopKey: ECKey = generateKey("dpop")

    /** The key the client attestation binds to, used to sign its proof of possession. */
    val clientPopKey: ECKey = generateKey("client-pop")

    /**
     * The certificate the issuer sees in the attestation's `x5c` header.
     *
     * Self-signed: the reference issuer is running without a trust validator service, so
     * it logs "Trusting all Wallet Providers" and accepts any chain. It does insist the
     * chain is *present*, and reads the signing key from it.
     */
    val attestationCertificate: X509Certificate = selfSign(attestationKey)

    init {
        // Key generation never reaches the network, so unlike every other operation in
        // the crypto trace it has to be reported from here.
        crypto?.record(
            flowId = "unit:$unitId",
            operation = "keygen",
            actor = "wallet",
            artifact = "Wallet unit key material",
            summary = "Four P-256 key pairs generated for this wallet unit: the device key a " +
                "credential will be bound to, the DPoP key that binds access tokens, the key the " +
                "client attestation confirms, and the key the testbed signs attestations with",
            algorithm = "ES256 (P-256)",
            keys = describe(),
            binds = mapOf(
                "wallet unit" to unitId,
                "attestation certificate" to attestationCertificate.subjectX500Principal.name,
            ),
            caveat = "Generated in software and held in this JVM's heap. On a certified wallet unit " +
                "these keys would be created inside a WSCD and be non-extractable; here they can be " +
                "read, copied and used from anywhere, which no counterparty can detect.",
            walletUnitId = unitId,
        )
    }

    /** The unit's public keys, by role, for the console's key panel and the trace. */
    fun describe(): List<KeyRef> = listOf(
        "device" to deviceKey,
        "dpop" to dpopKey,
        "client-pop" to clientPopKey,
        "wallet-provider" to attestationKey,
    ).mapNotNull { (role, key) ->
        runCatching {
            KeyRef(
                role = role,
                thumbprint = key.computeThumbprint().toString(),
                kty = key.keyType.value,
                crv = key.curve.name,
                kid = key.keyID,
                storage = "software (JVM heap)",
            )
        }.getOrNull()
    }

    /**
     * Mints the key attestation that OpenID4VCI 1.0 requires in the `key_attestation`
     * header of a JWT proof.
     *
     * A production wallet receives this from its wallet provider over an attested
     * channel. The claims here are the full set the reference issuer requires: drop any
     * one of iat, exp, attested_keys, key_storage, user_authentication, certification or
     * key_storage_status and it rejects the attestation.
     */
    fun keyAttestation(
        nonce: String? = null,
        keyStorageStatus: KeyStorageStatusEntry,
        flowId: String? = null,
        attestedKeys: List<ECKey> = listOf(deviceKey),
    ): KeyAttestationJWT {
        val now = Instant.now()
        val expiry = now.plusSeconds(300)

        val claims = JWTClaimsSet.Builder()
            .issueTime(Date.from(now))
            .expirationTime(Date.from(expiry))
            // One entry per credential copy in a batch; the issuer mints one credential
            // bound to each, and the JWT proof is signed by the first (index 0). Distinct
            // keys per copy mean the batch carries no shared value a pooling check could
            // correlate on (paper C4 unlinkability).
            .claim("attested_keys", attestedKeys.map { it.toPublicJWK().toJSONObject() })
            // The reference issuer advertises key_attestations_required with
            // iso_18045_high for both; a lower level is refused.
            .claim("key_storage", listOf("iso_18045_high"))
            .claim("user_authentication", listOf("iso_18045_high"))
            .claim("certification", "https://localhost/eudi-testbed/certification")
            .claim(
                "key_storage_status",
                mapOf(
                    "status" to mapOf(
                        "status_list" to mapOf(
                            "idx" to keyStorageStatus.index,
                            "uri" to keyStorageStatus.uri,
                        ),
                    ),
                    // Must outlive the issuer's preferred key storage status period, which
                    // is far longer than the attestation itself lives.
                    "exp" to now.plus(STATUS_VALIDITY).epochSecond,
                ),
            )
            .apply { if (nonce != null) claim("nonce", nonce) }
            .build()

        val jwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("key-attestation+jwt"))
                .x509CertChain(listOf(attestationCertificate.asX5cEntry()))
                .build(),
            claims,
        ).apply { sign(ECDSASigner(attestationKey)) }

        // The credential request that carries this attestation is encrypted to the
        // issuer, so the wire never shows it. Recorded here or not at all.
        if (flowId != null) {
            crypto?.record(
                flowId = flowId,
                operation = "sign",
                actor = "wallet-provider",
                artifact = "Key attestation",
                summary = "The wallet provider asserts the assurance level of the device key: where it " +
                    "is stored and how the user is authenticated before it is used",
                algorithm = "ES256",
                keys = describe().filter { it.role == "device" || it.role == "wallet-provider" },
                binds = buildMap {
                    put("attested keys", attestedKeys.size.toString())
                    put("key_storage", "iso_18045_high")
                    put("user_authentication", "iso_18045_high")
                    put(
                        "status reference",
                        "${keyStorageStatus.uri}#${keyStorageStatus.index}",
                    )
                    if (nonce != null) put("issuer nonce", nonce)
                    put("x5c subject", attestationCertificate.subjectX500Principal.name)
                },
                header = lenientJson.parseToJsonElement(jwt.header.toString()),
                payload = lenientJson.parseToJsonElement(claims.toString()),
                onWire = "sealed inside the encrypted credential request",
                caveat = "Asserts iso_18045_high for both key storage and user authentication while the " +
                    "private key is held in this JVM's heap and no user authentication happens at all. " +
                    "Signed by the testbed itself under a self-signed certificate; the issuer accepts it " +
                    "only because its trust validator is switched off. No protocol check can detect this.",
                compact = jwt.serialize(),
                walletUnitId = unitId,
            )
        }

        return KeyAttestationJWT(jwt)
    }

    /** Signs a client attestation as the wallet provider would. */
    fun signAsWalletProvider(header: JWSHeader, claims: JWTClaimsSet): SignedJWT =
        SignedJWT(header, claims).apply { sign(ECDSASigner(attestationKey)) }

    /** The signer the issuance flow hands to `ProofSpecification.JwtProof`. */
    fun proofSigner(
        nonce: String? = null,
        keyStorageStatus: KeyStorageStatusEntry,
        flowId: String? = null,
        attestedKeys: List<ECKey> = listOf(deviceKey),
    ): Signer<KeyAttestationJWT> {
        val attestation = keyAttestation(nonce, keyStorageStatus, flowId, attestedKeys)
        // The library assembles and signs the proof JWT itself, so the serialized form
        // is not available here; the nonce and the signing key are, and they are what
        // the proof actually commits to.
        if (flowId != null) {
            crypto?.record(
                flowId = flowId,
                operation = "sign",
                actor = "wallet",
                artifact = "Credential request proof (JWT)",
                summary = "Wallet proves control of the key the credential will be bound to, over a " +
                    "nonce the issuer chose so the proof cannot be pre-computed or replayed",
                algorithm = "ES256",
                keys = describe().filter { it.role == "device" },
                binds = buildMap {
                    if (nonce != null) put("issuer nonce (c_nonce)", nonce)
                    put("key attestation", "attached in the proof header")
                    if (attestedKeys.size > 1) put("batch size", attestedKeys.size.toString())
                },
                onWire = "sealed inside the encrypted credential request",
                walletUnitId = unitId,
            )
        }
        // The issuer verifies the proof signature against attested_keys[0], so the batch's
        // first key must be the one that signs.
        return EcSigner(attestedKeys.first(), attestation)
    }

    /**
     * A fresh batch of device keys for unlinkable batch issuance.
     *
     * Each credential copy the issuer returns is bound to a distinct one of these; index 0
     * also signs the credential-request proof. Generated per issuance and never kept as unit
     * state — the private half of each is persisted alongside the credential it binds, so the
     * copy can later be presented on its own.
     */
    fun newDeviceKeyBatch(size: Int): List<ECKey> =
        List(size) { generateKey("device-copy") }

    companion object {
        /** A throwaway self-signed certificate over [key], for the x5c header. */
        private fun selfSign(key: ECKey): X509Certificate {
            val now = Instant.now()
            val subject = X500Name("CN=EUDI Testbed Wallet Provider")
            val builder = JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minusSeconds(60)),
                Date.from(now.plusSeconds(365L * 24 * 60 * 60)),
                subject,
                key.toPublicKey(),
            )
            val signer = JcaContentSignerBuilder("SHA256withECDSA").build(key.toPrivateKey())
            return JcaX509CertificateConverter().getCertificate(builder.build(signer))
        }

        fun generateKey(id: String): ECKey =
            ECKeyGenerator(Curve.P_256)
                .keyID("$id-${System.nanoTime()}")
                .generate()
    }
}
