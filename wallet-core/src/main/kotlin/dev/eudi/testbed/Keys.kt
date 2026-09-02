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
 * The wallet's key material.
 *
 * [deviceKey] is the key a credential gets bound to and that later signs key-binding
 * JWTs when presenting. [attestationKey] stands in for the key a real wallet
 * provider would use to attest that the device key lives in secure hardware.
 */
class WalletKeys(
    val deviceKey: ECKey = generateKey("device"),
    private val attestationKey: ECKey = generateKey("wallet-provider"),
    /** Binds access tokens to this wallet via DPoP; the sample realm requires it. */
    val dpopKey: ECKey = generateKey("dpop"),
    /** The key the client attestation binds to, used to sign its proof of possession. */
    val clientPopKey: ECKey = generateKey("client-pop"),
) {

    /**
     * The certificate the issuer sees in the attestation's `x5c` header.
     *
     * Self-signed: the reference issuer is running without a trust validator service, so
     * it logs "Trusting all Wallet Providers" and accepts any chain. It does insist the
     * chain is *present*, and reads the signing key from it.
     */
    val attestationCertificate: X509Certificate = selfSign(attestationKey)

    /**
     * Mints the key attestation that OpenID4VCI 1.0 requires in the `key_attestation`
     * header of a JWT proof.
     *
     * A production wallet receives this from its wallet provider over an attested
     * channel. The claims here are the full set the reference issuer requires: drop any
     * one of iat, exp, attested_keys, key_storage, user_authentication, certification or
     * key_storage_status and it rejects the attestation.
     */
    fun keyAttestation(nonce: String? = null, keyStorageStatus: KeyStorageStatusEntry): KeyAttestationJWT {
        val now = Instant.now()
        val expiry = now.plusSeconds(300)

        val claims = JWTClaimsSet.Builder()
            .issueTime(Date.from(now))
            .expirationTime(Date.from(expiry))
            .claim("attested_keys", listOf(deviceKey.toPublicJWK().toJSONObject()))
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

        return KeyAttestationJWT(jwt)
    }

    /** Signs a client attestation as the wallet provider would. */
    fun signAsWalletProvider(header: JWSHeader, claims: JWTClaimsSet): SignedJWT =
        SignedJWT(header, claims).apply { sign(ECDSASigner(attestationKey)) }

    /** The signer the issuance flow hands to `ProofSpecification.JwtProof`. */
    fun proofSigner(nonce: String? = null, keyStorageStatus: KeyStorageStatusEntry): Signer<KeyAttestationJWT> =
        EcSigner(deviceKey, keyAttestation(nonce, keyStorageStatus))

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
