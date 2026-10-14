package dev.eudi.testbed

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.X509Certificate
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
    /** How many distinct attest keys the presented keys were attested by. 1 means co-resident. */
    val distinctAttestKeys: Int,
    val reason: String?,
)

/**
 * The **linking issuer** of the paper's countermeasure (§"The linking issuer role").
 *
 * It performs the one observation batch issuance has severed by presentation time: that
 * two keys are co-resident in a single WSCD. Its evidence is the WSCD's own key attestation,
 * as Android KeyMint produces it with an application attest key: each key arrives with its
 * attestation chain — the key's certificate, signed by the WSCD's attest key, then the attest
 * key's certificate up to an attestation root. A single-use link credential is issued only if
 * every key is attested by **one** attest key.
 *
 * Four checks carry the soundness; each closes a forgery:
 *  - the chain ends at a trusted attestation root, so a self-made "attest key" is worthless;
 *  - the attest key's own attestation says purposes == {ATTEST_KEY} and origin GENERATED. An
 *    ordinary WSCD key signs whatever it is given, so it could put Bob's key in a certificate;
 *    only its purpose gives it away (names do not: Android uses one subject for every key);
 *  - the attest key's attestation is the first one in the chain, counting from the root. Only
 *    that one was written with the platform's attestation key; a certificate below it was
 *    signed by whatever key the chain names, so an ordinary key could vouch for a fake attest
 *    key ("only the first occurrence of the extension in the chain can be trusted", Android's
 *    key attestation guide);
 *  - each key's attestation says origin GENERATED. KeyMint also attests imported keys with an
 *    attest key, but records origin IMPORTED, so this is what excludes keys made elsewhere.
 * An attest key signs nothing but the attestation of a key generated or imported in its own
 * WSCD, so a pooled pair necessarily arrives under two attest keys, and the linking issuer
 * refuses. [policy] adds what Android's guide requires of any attestation (validity at
 * [clock] time, the revocation status list) and what a wallet needs (verified boot, the app).
 *
 * This realises assumption `as:li` (the linking issuer is honest and issues a link only over
 * keys attested co-resident), with `as:wscd` grounded in the attest key. The attest key is a
 * stable per-WSCD value, so whoever plays this role can recognise a wallet across requests;
 * that is the privacy cost of observing co-residency, and an argument for giving the role to
 * the wallet provider, which already knows the device.
 */
class LinkingIssuer(
    private val crypto: CryptoSink,
    trustedRoots: List<X509Certificate>,
    private val policy: AttestationPolicy = AttestationPolicy(),
    private val clock: () -> Instant = Instant::now,
) {

    val id: String = "https://localhost/eudi-testbed/linking-issuer"
    val vct: String = "urn:eudi:link:1"

    private val signingKey: ECKey = ECKeyGenerator(Curve.P_256).keyID("linking-issuer-${System.nanoTime()}").generate()
    private val certificate = selfSign(signingKey)
    private val rootKeys: List<PublicKey> = trustedRoots.map { it.publicKey }

    /** The public key the verifier keeps on its trusted list to check link credentials. */
    fun trustedJwk(): ECKey = signingKey.toPublicJWK()

    /** One key that passed the attestation checks, and the attest key that vouches for it. */
    private class Attested(val key: ECKey, val attestKey: String)

    /**
     * Verify each key's attestation chain and, if a single attest key covers all of them,
     * issue a link credential over the keys.
     */
    fun issueLink(
        chains: List<List<X509Certificate>>,
        flowId: String,
        walletUnitId: String? = null,
    ): LinkResult {
        if (chains.isEmpty()) return refuse(flowId, walletUnitId, "no keys to link")
        val attested = chains.map { chain ->
            try {
                attested(chain)
            } catch (e: IllegalArgumentException) {
                return refuse(flowId, walletUnitId, e.message ?: "an attestation chain is invalid")
            }
        }

        val byAttestKey = attested.groupBy { it.attestKey }
        val allKeys = attested.map { it.key }.distinctBy { it.computeThumbprint().toString() }
        val thumbprints = allKeys.map { it.computeThumbprint().toString() }

        if (byAttestKey.size != 1) {
            crypto.record(
                flowId = flowId,
                operation = "verify",
                actor = "linking-issuer",
                artifact = "Key attestation chains",
                summary = "Linking issuer refused to issue a link credential: the presented keys were " +
                    "attested by ${byAttestKey.size} distinct attest keys, so they are not co-resident in one WSCD",
                keys = allKeys.map { it.asLinkedKeyRef() },
                binds = mapOf(
                    "distinct attest keys" to byAttestKey.size.toString(),
                    "keys" to thumbprints.joinToString(", "),
                ),
                caveat = "This is the countermeasure doing its job: credentials pooled from two wallet " +
                    "units are bound to keys generated in two WSCDs, and an attest key attests only keys " +
                    "generated in its own WSCD, so no single attest key covers both. Attack A is blocked here.",
                walletUnitId = walletUnitId,
            )
            return LinkResult(
                issued = false,
                credential = null,
                linkedKeyThumbprints = thumbprints,
                distinctAttestKeys = byAttestKey.size,
                reason = "keys attested by ${byAttestKey.size} distinct attest keys — not co-resident",
            )
        }

        val now = Instant.now()
        val claims = JWTClaimsSet.Builder()
            .issuer(id)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(300)))
            .jwtID(UUID.randomUUID().toString())
            .claim("vct", vct)
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
            summary = "Linking issuer verified that the ${allKeys.size} presented keys were generated in one " +
                "WSCD — all attested by the same attest key, itself attested up to the platform root — and " +
                "issued a single-use link credential binding them together",
            algorithm = "ES256",
            keys = allKeys.map { it.asLinkedKeyRef() },
            binds = mapOf(
                "linked keys" to thumbprints.joinToString(", "),
                "attest key" to byAttestKey.keys.single(),
                "linking issuer" to id,
                "jti (single-use)" to claims.jwtid,
            ),
            header = lenientJson.parseToJsonElement(linkCredential.header.toString()),
            payload = lenientJson.parseToJsonElement(claims.toString()),
            caveat = "Carries the device-key values in clear, so it is a stronger correlator than either " +
                "credential; it is single-use (fresh jti), so it cannot be reused across sessions (paper " +
                "§Unlinkability). The linking issuer saw the attest key, a stable per-WSCD value.",
            compact = linkCredential.serialize(),
            walletUnitId = walletUnitId,
        )

        return LinkResult(
            issued = true,
            credential = linkCredential.serialize(),
            linkedKeyThumbprints = thumbprints,
            distinctAttestKeys = 1,
            reason = null,
        )
    }

    /**
     * The checks on one key's chain (key, attest key, platform CAs, root). Throws
     * IllegalArgumentException with the reason when the chain does not prove the key was
     * generated in the WSCD that holds the attest key.
     */
    private fun attested(chain: List<X509Certificate>): Attested {
        require(chain.size >= 3) { "a key arrived without its attestation chain" }
        val leaf = chain[0]
        val key = runCatching { ECKey.parse(leaf).toPublicJWK() }.getOrNull()
            ?: throw IllegalArgumentException("an attested key is not an EC key")
        val label = key.computeThumbprint().toString().take(12)

        require(chain.zipWithNext().all { (child, parent) -> child.signedBy(parent.publicKey) }) {
            "the attestation chain of key $label does not verify"
        }
        val top = chain.last()
        require(rootKeys.any { it.encoded.contentEquals(top.publicKey.encoded) || top.signedBy(it) }) {
            "the attestation chain of key $label is not anchored at a trusted attestation root"
        }
        val now = Date.from(clock())
        chain.forEachIndexed { i, cert ->
            require(runCatching { cert.checkValidity(now) }.isSuccess) {
                "certificate $i of the attestation chain of key $label is valid only from ${cert.notBefore} " +
                    "to ${cert.notAfter}"
            }
            val serial = cert.serialNumber.toString(16)
            require(serial !in policy.revokedSerials) {
                "certificate $i of the attestation chain of key $label (serial $serial) is revoked"
            }
        }

        val attestKey = KeyDescription.of(chain[1])
        require(attestKey != null && attestKey.purposes == setOf(KeyDescription.PURPOSE_ATTEST_KEY)) {
            "key $label is certified by a key whose purposes are ${attestKey?.purposes ?: "unattested"}, not " +
                "{ATTEST_KEY(${KeyDescription.PURPOSE_ATTEST_KEY})}: an ordinary key signs whatever it is given, " +
                "so its certificate proves nothing about where the key was generated"
        }
        require(chain.drop(2).none { KeyDescription.present(it) }) {
            "the attest key of key $label is vouched for by a certificate that itself carries an attestation: " +
                "only the attestation closest to the root was written by secure hardware, so this attest key " +
                "may have been made up by an ordinary key"
        }
        require(attestKey.origin == KeyDescription.ORIGIN_GENERATED) {
            "the attest key of key $label was not generated in its WSCD"
        }
        require(
            attestKey.securityLevel in HARDWARE_LEVELS && attestKey.attestationSecurityLevel == attestKey.securityLevel,
        ) {
            "the attest key of key $label is not held by secure hardware (security level ${attestKey.securityLevel})"
        }
        val description = KeyDescription.of(leaf)
        require(description != null && description.origin == KeyDescription.ORIGIN_GENERATED) {
            "key $label was not generated in the WSCD (origin ${KeyDescription.originName(description?.origin)})"
        }
        require(
            description.securityLevel == attestKey.securityLevel &&
                description.attestationSecurityLevel == attestKey.attestationSecurityLevel,
        ) {
            "key $label and its attest key live at different security levels"
        }

        if (policy.requireVerifiedBoot) {
            require(attestKey.rootOfTrust?.verified == true && description.rootOfTrust?.verified == true) {
                "key $label comes from a device without a locked bootloader and verified boot " +
                    "(${description.rootOfTrust ?: "no root of trust"})"
            }
        }
        policy.trustedApps?.let { apps ->
            val app = description.applicationId
            require(app != null && apps.any { it.packageName in app.packageNames && it.signatureDigest in app.signatureDigests }) {
                "key $label was generated by ${app?.packageNames ?: "an unnamed app"}, which is not a trusted wallet app"
            }
        }
        return Attested(key, chain[1].publicKey.thumbprint())
    }

    private fun refuse(flowId: String, walletUnitId: String?, reason: String): LinkResult {
        crypto.record(
            flowId = flowId,
            operation = "verify",
            actor = "linking-issuer",
            artifact = "Key attestation chains",
            summary = "Linking issuer refused to issue a link credential: $reason",
            binds = mapOf("reason" to reason),
            walletUnitId = walletUnitId,
        )
        return LinkResult(issued = false, credential = null, linkedKeyThumbprints = emptyList(), distinctAttestKeys = 0, reason = reason)
    }

    companion object {
        private val HARDWARE_LEVELS = setOf(KeyDescription.SECURITY_LEVEL_TEE, KeyDescription.SECURITY_LEVEL_STRONGBOX)

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

/** True when this certificate's signature verifies under [key]. */
private fun X509Certificate.signedBy(key: PublicKey): Boolean =
    runCatching { verify(key) }.isSuccess

/** SHA-256 over the encoded public key, base64url: names an attest key whatever its algorithm. */
private fun PublicKey.thumbprint(): String =
    Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(encoded)).toString()

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
