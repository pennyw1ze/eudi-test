// Adversarial test against the PoP-based linking issuer at commit e528f5b (superseded by the
// attest-key check). Ran 4/4 green there: relayed-PoP bypass accepted. Kept as evidence.
package dev.eudi.testbed

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.nio.file.Files
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Adversarial check of the linking issuer: Attack A participants (Alice online, Bob online and
 * cooperating) try to obtain a link credential over Alice's PID key and Bob's degree key.
 * Bob never exports his private key; he only signs the relayed nonce, exactly as he already
 * signs his KB-JWT in the pooled presentation.
 */
class PoolingBypassTest {
    private val crypto = CryptoSink(SessionLog(Files.createTempDirectory("bypass")))
    private val linkingIssuer = LinkingIssuer(crypto)
    private val verifier = LinkingVerifier(listOf(linkingIssuer.trustedJwk()), crypto)

    private val alice = WalletKeys("alice")
    private val bob = WalletKeys("bob")
    private val nonce = UUID.randomUUID().toString() // the verifier's presentation nonce

    /** Runs on Bob's device: a PoP over the relayed nonce. Only the JWS leaves the device. */
    private fun popOnBobsDevice(challenge: String): String = SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType("key-pop+jwt")).build(),
        JWTClaimsSet.Builder()
            .claim("challenge", challenge)
            .claim("jkt", bob.deviceKey.toPublicJWK().computeThumbprint().toString())
            .issueTime(Date())
            .build(),
    ).apply { sign(ECDSASigner(bob.deviceKey)) }.serialize()

    /** Runs on Alice's device: ONE co-residency attestation, under ONE WUA key, listing both keys. */
    private fun bundleOnAlicesDevice(
        wuaKey: ECKey,
        wuaCert: X509Certificate,
        bobPublicKey: ECKey,
        bobPop: String,
    ): SignedJWT {
        val alicePop = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType("key-pop+jwt")).build(),
            JWTClaimsSet.Builder().claim("challenge", nonce).issueTime(Date()).build(),
        ).apply { sign(ECDSASigner(alice.deviceKey)) }.serialize()

        val claims = JWTClaimsSet.Builder()
            .issueTime(Date())
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .claim("challenge", nonce)
            .claim(
                "coresident_keys",
                listOf(
                    mapOf("jwk" to alice.deviceKey.toPublicJWK().toJSONObject(), "pop" to alicePop),
                    mapOf("jwk" to bobPublicKey.toJSONObject(), "pop" to bobPop),
                ),
            )
            .build()
        return SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("wua-coresidency+jwt"))
                .x509CertChain(listOf(wuaCert.asX5cEntry()))
                .build(),
            claims,
        ).apply { sign(ECDSASigner(wuaKey)) }
    }

    private fun presentedKeys() = listOf(alice.deviceKey.toPublicJWK(), bob.deviceKey.toPublicJWK())

    @Test
    fun `control - testbed's own honest per-unit attestations are rejected`() {
        val attestations = listOf(
            alice.coResidencyAttestation(listOf(alice.deviceKey), nonce),
            bob.coResidencyAttestation(listOf(bob.deviceKey), nonce),
        )
        val link = linkingIssuer.issueLink(attestations, nonce, "control")
        assertFalse(link.issued)
        assertEquals(2, link.distinctWua)
    }

    @Test
    fun `bypass 1 - Alice's genuine WUA key vouches for Bob's key using Bob's relayed PoP`() {
        val aliceWuaKey = WalletKeys::class.java.getDeclaredField("attestationKey")
            .apply { isAccessible = true }.get(alice) as ECKey

        val bobPop = popOnBobsDevice(nonce) // Bob → Alice: public key + PoP, no private key
        val attestation = bundleOnAlicesDevice(aliceWuaKey, alice.attestationCertificate, bob.deviceKey.toPublicJWK(), bobPop)

        val link = linkingIssuer.issueLink(listOf(attestation), nonce, "bypass1")
        assertTrue(link.issued, "linking issuer refused: ${link.reason}")
        assertEquals(1, link.distinctWua)

        val verdict = verifier.verify(presentedKeys(), link, "bypass1")
        assertTrue(verdict.accepted, "verifier rejected: ${verdict.reason}")
        println("BYPASS 1: link issued over Alice+Bob keys, verifier accepted = ${verdict.accepted}")
    }

    @Test
    fun `bypass 2 - a freshly minted self-signed WUA is accepted too`() {
        val forgedWua = WalletKeys.generateKey("attacker-wua")
        val now = Instant.now()
        val subject = X500Name("CN=Anything")
        val cert = JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(3600)),
                subject, forgedWua.toPublicKey(),
            ).build(JcaContentSignerBuilder("SHA256withECDSA").build(forgedWua.toPrivateKey())),
        )

        val bobPop = popOnBobsDevice(nonce)
        val attestation = bundleOnAlicesDevice(forgedWua, cert, bob.deviceKey.toPublicJWK(), bobPop)

        val link = linkingIssuer.issueLink(listOf(attestation), nonce, "bypass2")
        assertTrue(link.issued, "linking issuer refused: ${link.reason}")
        val verdict = verifier.verify(presentedKeys(), link, "bypass2")
        assertTrue(verdict.accepted, "verifier rejected: ${verdict.reason}")
        println("BYPASS 2: forged WUA, link issued, verifier accepted = ${verdict.accepted}")
    }

    @Test
    fun `link credential is not bound to the presentation - replay under a new nonce is accepted`() {
        val first = linkingIssuer.issueLink(
            listOf(alice.coResidencyAttestation(listOf(alice.deviceKey), nonce)), nonce, "replay-a",
        )
        assertTrue(first.issued)
        // A later presentation with a different nonce: the verifier is handed the old link.
        val verdict = verifier.verify(listOf(alice.deviceKey.toPublicJWK()), first, "replay-b")
        assertTrue(verdict.accepted, "verifier rejected the replay: ${verdict.reason}")
        println("REPLAY: old link accepted for a new presentation = ${verdict.accepted}")
    }
}
