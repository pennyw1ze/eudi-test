package dev.eudi.testbed

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.time.Instant
import java.util.Date
import java.util.UUID

/** The outcome of asking the linking issuer to link a set of keys. */
data class LinkResult(
    /** Whether a link credential was issued at all. False means the keys were not co-resident. */
    val issued: Boolean,
    /** The compact JWS link credential, when [issued]. */
    val credential: String?,
    /** Thumbprints of the keys the link credential covers. */
    val linkedKeyThumbprints: List<String>,
    /** How many distinct WUAs the presented keys were attested under. 1 means co-resident. */
    val distinctWua: Int,
    val reason: String?,
)

/**
 * The **linking issuer** of the paper's countermeasure (§"The linking issuer role").
 *
 * It performs the one observation batch issuance has severed by presentation time: that
 * two keys are co-resident in a single WSCD. It reads a WUA-signed co-residency
 * attestation for each key (minted by that key's wallet unit, see
 * [WalletKeys.coResidencyAttestation]), verifies the WUA signature and a fresh proof of
 * possession per key, and — only if every key was attested under **one** WUA — issues a
 * single-use link credential binding exactly those keys together.
 *
 * The check is the whole point: pooled credentials come from two units, so they arrive
 * with two attestations under two different WUA keys, and the linking issuer refuses.
 * A genuine holder presenting two of their own credentials has both keys under one WUA,
 * and is linked. This realises assumption `as:li` (the linking issuer is honest and
 * issues a link only over keys attested co-resident under one WUA).
 *
 * Trust of the WUAs themselves is stubbed to accept any chain, mirroring the reference
 * issuer's "Trusting all Wallet Providers"; what makes the role sound here is not who
 * signed the WUA but that a valid proof of possession accompanies every linked key.
 */
class LinkingIssuer(private val crypto: CryptoSink) {

    val id: String = "https://localhost/eudi-testbed/linking-issuer"
    val vct: String = "urn:eudi:link:1"

    private val signingKey: ECKey = ECKeyGenerator(Curve.P_256).keyID("linking-issuer-${System.nanoTime()}").generate()
    private val certificate = selfSign(signingKey)

    /** The public key the verifier keeps on its trusted list to check link credentials. */
    fun trustedJwk(): ECKey = signingKey.toPublicJWK()

    /**
     * Verify the co-residency attestations and, if the keys are co-resident under one WUA,
     * issue a link credential over them.
     */
    fun issueLink(
        attestations: List<SignedJWT>,
        challenge: String,
        flowId: String,
        walletUnitId: String? = null,
    ): LinkResult {
        val perWua = mutableMapOf<String, MutableList<ECKey>>()

        for (attestation in attestations) {
            val wuaKey = attestation.x5cLeafKey()
                ?: return refuse(flowId, walletUnitId, "a co-residency attestation carried no usable WUA certificate")
            if (!attestation.verifiedBy(wuaKey)) {
                return refuse(flowId, walletUnitId, "a co-residency attestation's WUA signature did not verify")
            }
            val claims = attestation.jwtClaimsSet
            if (claims.getStringClaim("challenge") != challenge) {
                return refuse(flowId, walletUnitId, "a co-residency attestation was not bound to this presentation's challenge")
            }
            val wuaThumbprint = wuaKey.computeThumbprint().toString()

            val entries = runCatching { claims.getListClaim("coresident_keys") }.getOrNull().orEmpty()
            if (entries.isEmpty()) {
                return refuse(flowId, walletUnitId, "a co-residency attestation listed no keys")
            }
            for (entry in entries) {
                @Suppress("UNCHECKED_CAST")
                val map = entry as? Map<String, Any?> ?: return refuse(flowId, walletUnitId, "malformed co-residency key entry")
                @Suppress("UNCHECKED_CAST")
                val jwkMap = map["jwk"] as? Map<String, Any?>
                    ?: return refuse(flowId, walletUnitId, "co-residency key entry carried no jwk")
                val popCompact = map["pop"] as? String
                    ?: return refuse(flowId, walletUnitId, "co-residency key entry carried no proof of possession")

                val key = runCatching { JWK.parse(jwkMap as Map<String, Any>).toECKey().toPublicJWK() }.getOrNull()
                    ?: return refuse(flowId, walletUnitId, "co-residency key entry carried an unparseable jwk")
                val keyThumbprint = key.computeThumbprint().toString()

                // Proof of possession: only the holder of this key's private half could have
                // signed the challenge under it. This is what stops one unit vouching for
                // another unit's key.
                val pop = runCatching { SignedJWT.parse(popCompact) }.getOrNull()
                    ?: return refuse(flowId, walletUnitId, "co-residency proof of possession was unparseable")
                if (!pop.verifiedBy(key)) {
                    return refuse(flowId, walletUnitId, "proof of possession did not verify under key $keyThumbprint")
                }
                if (pop.jwtClaimsSet.getStringClaim("challenge") != challenge) {
                    return refuse(flowId, walletUnitId, "proof of possession was not bound to this challenge")
                }

                perWua.getOrPut(wuaThumbprint) { mutableListOf() }.add(key)
            }
        }

        val distinctWua = perWua.size
        val allKeys = perWua.values.flatten().distinctBy { it.computeThumbprint().toString() }
        val thumbprints = allKeys.map { it.computeThumbprint().toString() }

        if (distinctWua != 1) {
            crypto.record(
                flowId = flowId,
                operation = "verify",
                actor = "linking-issuer",
                artifact = "Co-residency attestations",
                summary = "Linking issuer refused to issue a link credential: the presented keys were " +
                    "attested under $distinctWua distinct WUAs, so they are not co-resident in one WSCD",
                keys = allKeys.map { it.asLinkedKeyRef() },
                binds = mapOf(
                    "distinct WUAs" to distinctWua.toString(),
                    "keys" to thumbprints.joinToString(", "),
                ),
                caveat = "This is the countermeasure doing its job: two credentials pooled from two " +
                    "wallet units carry two WUAs, and no single WUA can prove possession of both device " +
                    "keys, so co-residency cannot be certified. Attack A is blocked here.",
                walletUnitId = walletUnitId,
            )
            return LinkResult(
                issued = false,
                credential = null,
                linkedKeyThumbprints = thumbprints,
                distinctWua = distinctWua,
                reason = "keys attested under $distinctWua distinct WUAs — not co-resident",
            )
        }

        val now = Instant.now()
        val claims = JWTClaimsSet.Builder()
            .issuer(id)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(300)))
            .jwtID(UUID.randomUUID().toString())
            .claim("vct", vct)
            .claim("challenge", challenge)
            .claim("linked_keys", allKeys.map { it.toJSONObject() })
            .claim("linked_key_thumbprints", thumbprints)
            .build()

        val linkCredential = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("link-credential+jwt"))
                .x509CertChain(listOf(certificate.asX5cEntry()))
                .build(),
            claims,
        ).apply { sign(ECDSASigner(signingKey)) }

        crypto.record(
            flowId = flowId,
            operation = "sign",
            actor = "linking-issuer",
            artifact = "Link credential",
            summary = "Linking issuer certified that the ${allKeys.size} presented keys are co-resident " +
                "in one WSCD and issued a single-use link credential binding them together",
            algorithm = "ES256",
            keys = allKeys.map { it.asLinkedKeyRef() },
            binds = mapOf(
                "linked keys" to thumbprints.joinToString(", "),
                "linking issuer" to id,
                "jti (single-use)" to claims.jwtid,
            ),
            header = lenientJson.parseToJsonElement(linkCredential.header.toString()),
            payload = lenientJson.parseToJsonElement(claims.toString()),
            caveat = "Carries the two device-key values in clear, so it is a stronger correlator than " +
                "either credential; it is single-use (fresh jti, bound to this presentation's challenge) " +
                "so it cannot be replayed or reused across sessions (paper §Unlinkability).",
            compact = linkCredential.serialize(),
            walletUnitId = walletUnitId,
        )

        return LinkResult(
            issued = true,
            credential = linkCredential.serialize(),
            linkedKeyThumbprints = thumbprints,
            distinctWua = 1,
            reason = null,
        )
    }

    private fun refuse(flowId: String, walletUnitId: String?, reason: String): LinkResult {
        crypto.record(
            flowId = flowId,
            operation = "verify",
            actor = "linking-issuer",
            artifact = "Co-residency attestations",
            summary = "Linking issuer refused to issue a link credential: $reason",
            binds = mapOf("reason" to reason),
            walletUnitId = walletUnitId,
        )
        return LinkResult(issued = false, credential = null, linkedKeyThumbprints = emptyList(), distinctWua = 0, reason = reason)
    }

    companion object {
        private fun selfSign(key: ECKey): java.security.cert.X509Certificate {
            val now = Instant.now()
            val subject = X500Name("CN=EUDI Testbed Linking Issuer")
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
    }
}

/** The EC public key in a JWS's `x5c` leaf certificate, if present and parseable. */
internal fun SignedJWT.x5cLeafKey(): ECKey? = runCatching {
    val leaf = header.x509CertChain?.firstOrNull()?.decode() ?: return null
    val cert = X509CertUtils.parse(leaf) ?: return null
    ECKey.parse(cert)
}.getOrNull()

/** True when this JWS verifies under [key]'s public half. */
internal fun SignedJWT.verifiedBy(key: ECKey): Boolean =
    runCatching { verify(ECDSAVerifier(key.toPublicJWK())) }.getOrDefault(false)

/** A public [KeyRef] for a linked device key, so the console can colour it in the trace. */
internal fun ECKey.asLinkedKeyRef(): KeyRef = KeyRef(
    role = "device",
    thumbprint = computeThumbprint().toString(),
    kty = keyType?.value,
    crv = curve?.name,
    kid = keyID,
    storage = "software (JVM heap)",
)
