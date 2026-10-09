package dev.eudi.testbed

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.x500.X500Name
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.nio.file.Files
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The linking issuer decides co-residency from attest-key attestation chains. Alice and Bob
 * are two wallet units on the same emulated platform; the attacks are the ones a pooling pair
 * can actually mount, since neither can reach inside a WSCD.
 */
class LinkingIssuerTest {
    private val crypto = CryptoSink(SessionLog(Files.createTempDirectory("linking-issuer-test")))
    private val platform = AttestationAuthority()
    private val linkingIssuer = LinkingIssuer(crypto, trustedRoots = listOf(platform.root))
    private val verifier = LinkingVerifier(listOf(linkingIssuer.trustedJwk()), crypto)

    private val alice = WalletKeys("alice", attestation = platform)
    private val bob = WalletKeys("bob", attestation = platform)

    private fun chainOf(unit: WalletKeys, key: com.nimbusds.jose.jwk.ECKey) =
        requireNotNull(unit.attestationChain(key)) { "no chain for key" }

    @Test
    fun `genuine holder - keys generated in one WSCD are linked and the verifier accepts`() {
        val (k1, k2) = alice.newDeviceKeyBatch(2)
        val link = linkingIssuer.issueLink(listOf(chainOf(alice, k1), chainOf(alice, k2)), "genuine")
        assertTrue(link.issued, link.reason)

        val verdict = verifier.verify(listOf(k1.toPublicJWK(), k2.toPublicJWK()), link, "genuine")
        assertTrue(verdict.accepted, verdict.reason)
    }

    @Test
    fun `pooling - Alice forwards Bob's genuine chain next to hers and is refused`() {
        val link = linkingIssuer.issueLink(
            listOf(chainOf(alice, alice.deviceKey), chainOf(bob, bob.deviceKey)),
            "pooled",
        )
        assertFalse(link.issued)
        assertEquals(2, link.distinctAttestKeys)
    }

    @Test
    fun `forgery - an ordinary WSCD key cannot stand in for the attest key`() {
        // Alice's ordinary device key signs anything, so she makes it certify Bob's key, with
        // Bob's genuine KeyDescription (origin GENERATED) and the subject every key carries.
        val bobLeaf = chainOf(bob, bob.deviceKey).first()
        val aliceChain = chainOf(alice, alice.deviceKey)
        val forged = issueCertificate(
            subject = X500Name("CN=Android Keystore Key"),
            publicKey = bob.deviceKey.toPublicKey(),
            issuer = X500Name.getInstance(aliceChain.first().subjectX500Principal.encoded),
            signingKey = alice.deviceKey,
            validUntil = Instant.now().plusSeconds(3600),
            description = KeyDescription.of(bobLeaf),
        )

        val link = linkingIssuer.issueLink(listOf(aliceChain, listOf(forged) + aliceChain), "forgery")
        assertFalse(link.issued)
        assertTrue(link.reason!!.contains("ATTEST_KEY"), link.reason)
    }

    @Test
    fun `a WSCD outside the trusted attestation PKI is refused`() {
        val mallory = WalletKeys("mallory", attestation = AttestationAuthority())
        val (k1, k2) = mallory.newDeviceKeyBatch(2)

        val link = linkingIssuer.issueLink(listOf(chainOf(mallory, k1), chainOf(mallory, k2)), "rogue")
        assertFalse(link.issued)
        assertTrue(link.reason!!.contains("trusted attestation root"), link.reason)
    }

    @Test
    fun `a key without its attestation chain is refused`() {
        val link = linkingIssuer.issueLink(listOf(chainOf(alice, alice.deviceKey), emptyList()), "missing")
        assertFalse(link.issued)
    }

    /**
     * The same checks against chains from a real phone, recorded by attestkey-probe/ (run
     * ./run.sh there first; skipped otherwise). Google's attestation roots are the anchors.
     */
    @Test
    fun `real device chains - co-resident keys linked, forgery and cross-WSCD pairs refused`() {
        val probe = File("../attestkey-probe")
        val result = probe.resolve("results").listFiles { f -> f.name.startsWith("akprobe-") }?.minByOrNull { it.name }
        val roots = probe.resolve("google_roots.json")
        assumeTrue(result != null && roots.exists(), "no attestkey-probe results on this machine")

        val googleRoots = Json.parseToJsonElement(roots.readText()).jsonArray.map {
            cf.generateCertificate(it.jsonPrimitive.content.byteInputStream()) as X509Certificate
        }
        val deviceIssuer = LinkingIssuer(crypto, trustedRoots = googleRoots)
        val levels = Json.parseToJsonElement(result!!.readText()).jsonObject["levels"]!!.jsonObject

        val firstKeys = mutableListOf<List<X509Certificate>>()
        for ((name, element) in levels) {
            val level = element.jsonObject
            val akChain = certs(level, "ak")
            // Keystore returns only the leaf for an AK-attested key; the AK's chain completes it.
            val k1 = listOf(certs(level, "k1").first()) + akChain
            val k2 = listOf(certs(level, "k2").first()) + akChain
            firstKeys += k1

            val genuine = deviceIssuer.issueLink(listOf(k1, k2), "device-$name")
            assertTrue(genuine.issued, "$name: ${genuine.reason}")

            val forgery = level["forgery"]!!.jsonObject
            val forged = certificate(
                b64(forgery, "tbs"),
                b64(forgery, "signature"),
            )
            val signerChain = forgery["signer_chain"]!!.jsonArray.map { cert(it.jsonPrimitive.content) }
            val refused = deviceIssuer.issueLink(listOf(k1, listOf(forged) + signerChain), "device-$name-forgery")
            assertFalse(refused.issued, "$name: forged attestation accepted")
            assertTrue(refused.reason!!.contains("ATTEST_KEY"), refused.reason)
        }
        if (firstKeys.size > 1) {
            // StrongBox and TEE are two KeyMint instances, each with its own attest key.
            val cross = deviceIssuer.issueLink(firstKeys, "device-cross")
            assertFalse(cross.issued)
            assertEquals(firstKeys.size, cross.distinctAttestKeys)
        }
    }

    private val cf = CertificateFactory.getInstance("X.509")

    private fun cert(b64: String) = cf.generateCertificate(Base64.getDecoder().decode(b64).inputStream()) as X509Certificate

    private fun certs(level: JsonObject, key: String) =
        level[key]!!.jsonObject["chain"]!!.jsonArray.map { cert(it.jsonPrimitive.content) }

    private fun b64(o: JsonObject, key: String): ByteArray = Base64.getDecoder().decode(o[key]!!.jsonPrimitive.content)

    /** Reassembles a certificate from its body and an ECDSA-SHA256 signature, byte for byte. */
    private fun certificate(tbs: ByteArray, signature: ByteArray): X509Certificate {
        val ecdsaWithSha256 = byteArrayOf(0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x04, 0x03, 0x02)
        val body = tbs + ecdsaWithSha256 + der(0x03, byteArrayOf(0) + signature)
        return cf.generateCertificate(der(0x30, body).inputStream()) as X509Certificate
    }

    private fun der(tag: Int, content: ByteArray): ByteArray {
        val n = content.size
        val length = when {
            n < 0x80 -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        }
        return byteArrayOf(tag.toByte()) + length + content
    }
}
