package dev.eudi.testbed

import com.nimbusds.jose.jwk.ECKey
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.util.Date
import java.util.concurrent.ConcurrentHashMap

/**
 * The part of Android's KeyMint attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) that the
 * co-residency check reads: where the key lives, what it may be used for, whether it was
 * generated inside the secure hardware, the device's boot state and the app that asked for
 * the key. The encoding follows Android's KeyDescription schema, so [of] reads certificates
 * from a real device as well as the emulated ones below.
 */
class KeyDescription(
    /** KeyMint security level (keyMintSecurityLevel). */
    val securityLevel: Int,
    val challenge: ByteArray,
    /** Hardware-enforced purposes. */
    val purposes: Set<Int>,
    /** Hardware-enforced origin; [ORIGIN_GENERATED] means it never existed outside the hardware. */
    val origin: Int?,
    /** Security level of the attestation itself (attestationSecurityLevel). */
    val attestationSecurityLevel: Int = securityLevel,
    /** Hardware-enforced boot state of the device when the key was created. */
    val rootOfTrust: RootOfTrust? = null,
    /**
     * Software-enforced: Android's keystore writes it, not the secure hardware, so it is only as
     * trustworthy as the operating system, which [rootOfTrust] vouches for.
     */
    val applicationId: AttestationApplicationId? = null,
) {
    fun toAsn1(): ASN1Encodable = DERSequence(
        arrayOf(
            ASN1Integer(KEYMINT_VERSION),
            ASN1Enumerated(attestationSecurityLevel),
            ASN1Integer(KEYMINT_VERSION),
            ASN1Enumerated(securityLevel),
            DEROctetString(challenge),
            DEROctetString(ByteArray(0)), // uniqueId: never requested
            DERSequence( // softwareEnforced
                listOfNotNull(
                    applicationId?.let { DERTaggedObject(true, TAG_ATTESTATION_APPLICATION_ID, DEROctetString(it.toAsn1().toASN1Primitive().encoded)) },
                ).toTypedArray(),
            ),
            DERSequence( // hardwareEnforced, in tag order
                listOfNotNull(
                    DERTaggedObject(true, TAG_PURPOSE, DERSet(purposes.map { ASN1Integer(it.toLong()) }.toTypedArray())),
                    DERTaggedObject(true, TAG_ALGORITHM, ASN1Integer(ALGORITHM_EC)),
                    DERTaggedObject(true, TAG_KEY_SIZE, ASN1Integer(256)),
                    DERTaggedObject(true, TAG_EC_CURVE, ASN1Integer(EC_CURVE_P256)),
                    origin?.let { DERTaggedObject(true, TAG_ORIGIN, ASN1Integer(it.toLong())) },
                    rootOfTrust?.let { DERTaggedObject(true, TAG_ROOT_OF_TRUST, it.toAsn1()) },
                ).toTypedArray(),
            ),
        ),
    )

    companion object {
        const val OID = "1.3.6.1.4.1.11129.2.1.17"
        const val SECURITY_LEVEL_SOFTWARE = 0
        const val SECURITY_LEVEL_TEE = 1
        const val SECURITY_LEVEL_STRONGBOX = 2
        const val PURPOSE_SIGN = 2
        const val PURPOSE_ATTEST_KEY = 7
        const val ORIGIN_GENERATED = 0
        const val ORIGIN_IMPORTED = 2
        const val ORIGIN_SECURELY_IMPORTED = 4

        /** KeyOrigin names, as in KeyMint's KeyOrigin.aidl. */
        fun originName(origin: Int?): String =
            when (origin) {
                null -> "unattested"
                0 -> "GENERATED"
                1 -> "DERIVED"
                2 -> "IMPORTED"
                3 -> "RESERVED"
                4 -> "SECURELY_IMPORTED"
                else -> origin.toString()
            }

        private const val KEYMINT_VERSION = 300L
        private const val TAG_PURPOSE = 1
        private const val TAG_ALGORITHM = 2
        private const val TAG_KEY_SIZE = 3
        private const val TAG_EC_CURVE = 10
        private const val TAG_ORIGIN = 702
        private const val TAG_ROOT_OF_TRUST = 704
        private const val TAG_ATTESTATION_APPLICATION_ID = 709
        private const val ALGORITHM_EC = 3L
        private const val EC_CURVE_P256 = 1L

        /** True when the certificate carries an attestation extension at all, parseable or not. */
        fun present(cert: X509Certificate): Boolean = cert.getExtensionValue(OID) != null

        /** The certificate's KeyDescription, or null when it carries none or it does not parse. */
        fun of(cert: X509Certificate): KeyDescription? = runCatching {
            val raw = cert.getExtensionValue(OID) ?: return null
            val fields = ASN1Sequence.getInstance(ASN1OctetString.getInstance(raw).octets)
            val software = ASN1Sequence.getInstance(fields.getObjectAt(6)).map { ASN1TaggedObject.getInstance(it) }
            val hardware = ASN1Sequence.getInstance(fields.getObjectAt(7)).map { ASN1TaggedObject.getInstance(it) }
            val purposes = hardware.firstOrNull { it.tagNo == TAG_PURPOSE }
                ?.let { tagged -> ASN1Set.getInstance(tagged.explicitBaseObject).map { ASN1Integer.getInstance(it).intValueExact() } }
                .orEmpty()
                .toSet()
            val origin = hardware.firstOrNull { it.tagNo == TAG_ORIGIN }
                ?.let { ASN1Integer.getInstance(it.explicitBaseObject).intValueExact() }
            KeyDescription(
                securityLevel = ASN1Enumerated.getInstance(fields.getObjectAt(3)).intValueExact(),
                challenge = ASN1OctetString.getInstance(fields.getObjectAt(4)).octets,
                purposes = purposes,
                origin = origin,
                attestationSecurityLevel = ASN1Enumerated.getInstance(fields.getObjectAt(1)).intValueExact(),
                rootOfTrust = hardware.firstOrNull { it.tagNo == TAG_ROOT_OF_TRUST }
                    ?.let { RootOfTrust.of(ASN1Sequence.getInstance(it.explicitBaseObject)) },
                applicationId = software.firstOrNull { it.tagNo == TAG_ATTESTATION_APPLICATION_ID }
                    ?.let { AttestationApplicationId.of(ASN1OctetString.getInstance(it.explicitBaseObject).octets) },
            )
        }.getOrNull()
    }
}

/** KeyMint's RootOfTrust: whether the bootloader is locked and what verified boot concluded. */
data class RootOfTrust(val deviceLocked: Boolean, val verifiedBootState: Int) {
    /** Locked bootloader and verified boot state Verified: the OS on the device is the vendor's. */
    val verified: Boolean get() = deviceLocked && verifiedBootState == VERIFIED_BOOT_VERIFIED

    fun toAsn1(): ASN1Encodable = DERSequence(
        arrayOf(
            DEROctetString(ByteArray(32)), // verifiedBootKey
            ASN1Boolean.getInstance(deviceLocked),
            ASN1Enumerated(verifiedBootState),
            DEROctetString(ByteArray(32)), // verifiedBootHash
        ),
    )

    companion object {
        const val VERIFIED_BOOT_VERIFIED = 0
        const val VERIFIED_BOOT_UNVERIFIED = 2
        val LOCKED_VERIFIED = RootOfTrust(deviceLocked = true, verifiedBootState = VERIFIED_BOOT_VERIFIED)

        fun of(seq: ASN1Sequence) = RootOfTrust(
            deviceLocked = ASN1Boolean.getInstance(seq.getObjectAt(1)).isTrue,
            verifiedBootState = ASN1Enumerated.getInstance(seq.getObjectAt(2)).intValueExact(),
        )
    }
}

/**
 * KeyMint's AttestationApplicationId: the packages of the app that asked for the key and the
 * SHA-256 digests of its signing certificates (lowercase hex).
 */
data class AttestationApplicationId(val packageNames: Set<String>, val signatureDigests: Set<String>) {
    fun toAsn1(): ASN1Encodable = DERSequence(
        arrayOf(
            DERSet(packageNames.map { DERSequence(arrayOf(DEROctetString(it.toByteArray()), ASN1Integer(1))) }.toTypedArray()),
            DERSet(signatureDigests.map { DEROctetString(it.hexToByteArray()) }.toTypedArray()),
        ),
    )

    companion object {
        fun of(der: ByteArray): AttestationApplicationId {
            val seq = ASN1Sequence.getInstance(der)
            return AttestationApplicationId(
                packageNames = ASN1Set.getInstance(seq.getObjectAt(0)).map {
                    String(ASN1OctetString.getInstance(ASN1Sequence.getInstance(it).getObjectAt(0)).octets)
                }.toSet(),
                signatureDigests = ASN1Set.getInstance(seq.getObjectAt(1)).map {
                    ASN1OctetString.getInstance(it).octets.toHexString()
                }.toSet(),
            )
        }
    }
}

/** A wallet app whose keys a linking issuer accepts: package name and signing-certificate digest. */
data class TrustedApp(val packageName: String, val signatureDigest: String)

/** What a linking issuer requires of a device and its attestation PKI, beyond a sound chain. */
data class AttestationPolicy(
    /** Serials (lowercase hex) that Google's attestation status list marks REVOKED or SUSPENDED. */
    val revokedSerials: Set<String> = emptySet(),
    /** Locked bootloader and verified boot, which the software-enforced application id relies on. */
    val requireVerifiedBoot: Boolean = true,
    /** Wallet apps whose keys may be linked; null accepts keys of any app. */
    val trustedApps: Set<TrustedApp>? = null,
)

/**
 * Google's attestation status list (https://android.googleapis.com/attestation/status): serial
 * numbers, in lowercase hex, of attestation certificates that are REVOKED or SUSPENDED. Every
 * certificate of a chain must be checked against it.
 */
object AttestationStatusList {
    fun revokedSerials(json: String): Set<String> =
        lenientJson.parseToJsonElement(json).jsonObject["entries"]?.jsonObject.orEmpty()
            .filterValues { it.jsonObject["status"]?.jsonPrimitive?.content in setOf("REVOKED", "SUSPENDED") }
            .keys
}

/**
 * Emulates the platform's attestation PKI: on Android, Google's attestation root and the
 * factory-provisioned batch key every secure element of a model carries.
 *
 * One batch key is shared by every emulated WSCD, as a real factory key is shared by at least
 * 100,000 devices of a model (Android CDD §9.11). It therefore says "a genuine secure element
 * of this type", never "this device", which is why co-residency rests on the per-WSCD attest
 * key and not on the batch key.
 */
class AttestationAuthority {
    private val rootKey: ECKey = WalletKeys.generateKey("attestation-root")
    private val batchKey: ECKey = WalletKeys.generateKey("attestation-batch")

    /** The trust anchor a linking issuer checks attestation chains against. */
    val root: X509Certificate = issueCertificate(
        subject = X500Name("CN=EUDI Testbed Attestation Root"),
        publicKey = rootKey.toPublicKey(),
        issuer = X500Name("CN=EUDI Testbed Attestation Root"),
        signingKey = rootKey,
        validUntil = Instant.now().plusSeconds(20L * 365 * 24 * 60 * 60),
        ca = true,
    )

    private val batchCertificate: X509Certificate = issueCertificate(
        subject = X500Name("CN=EUDI Testbed StrongBox Batch"),
        publicKey = batchKey.toPublicKey(),
        issuer = X500Name.getInstance(root.subjectX500Principal.encoded),
        signingKey = rootKey,
        validUntil = Instant.now().plusSeconds(10L * 365 * 24 * 60 * 60),
        ca = true,
    )

    /**
     * A new WSCD of this platform, with the batch key provisioned into it as in the factory,
     * on a device in boot state [rootOfTrust], used by the wallet app [app].
     */
    fun newWscd(
        unitId: String,
        rootOfTrust: RootOfTrust = RootOfTrust.LOCKED_VERIFIED,
        app: AttestationApplicationId = TESTBED_WALLET,
    ): EmulatedWscd = EmulatedWscd(unitId, batchKey, listOf(batchCertificate, root), rootOfTrust, app)

    companion object {
        /** The one platform every wallet unit of this testbed runs on. */
        val platform: AttestationAuthority by lazy { AttestationAuthority() }

        /** The testbed's wallet app, as Android's keystore would name it in an attestation. */
        val TESTBED_WALLET = AttestationApplicationId(
            packageNames = setOf("dev.eudi.testbed.wallet"),
            signatureDigests = setOf(
                java.security.MessageDigest.getInstance("SHA-256")
                    .digest("EUDI testbed wallet signing certificate".toByteArray())
                    .toHexString(),
            ),
        )

        /** [TESTBED_WALLET] as the linking issuer's policy names it. */
        val TESTBED_WALLET_APP = TrustedApp(TESTBED_WALLET.packageNames.single(), TESTBED_WALLET.signatureDigests.single())
    }
}

/**
 * One wallet unit's emulated WSCD, modelled on Android KeyMint with an application attest key
 * (`PURPOSE_ATTEST_KEY` + `setAttestKeyAlias`).
 *
 * At creation it generates an attest key and certifies it with the factory batch key. Every
 * device key it then generates comes with an attestation certificate signed by that attest key,
 * recording origin GENERATED. The attest key never leaves this object and nothing here signs
 * arbitrary data with it — the only thing it signs is the attestation of a key generated right
 * here, as on a real device, where KeyMint refuses any other use with INCOMPATIBLE_PURPOSE and
 * attests only inside key generation or import. Import is the one way a key made elsewhere gets
 * under the attest key, and KeyMint records it: an imported key's attestation says origin
 * IMPORTED (KeyMint's importKey contract), which [importKey] reproduces. Two keys whose
 * certificates carry the same attest key and origin GENERATED were therefore generated in the
 * same WSCD.
 */
class EmulatedWscd internal constructor(
    val unitId: String,
    batchKey: ECKey,
    private val batchChain: List<X509Certificate>,
    private val rootOfTrust: RootOfTrust,
    private val app: AttestationApplicationId,
) {
    private val attestKey: ECKey = WalletKeys.generateKey("attest-key")
    private val random = SecureRandom()

    private val attestKeyCertificate: X509Certificate = issueCertificate(
        subject = KEYSTORE_SUBJECT,
        publicKey = attestKey.toPublicKey(),
        issuer = X500Name.getInstance(batchChain.first().subjectX500Principal.encoded),
        signingKey = batchKey,
        validUntil = KEYSTORE_NOT_AFTER,
        description = description(setOf(KeyDescription.PURPOSE_ATTEST_KEY), KeyDescription.ORIGIN_GENERATED),
    )

    /** Attestation chains of the keys generated here, by JWK thumbprint. */
    private val chains = ConcurrentHashMap<String, List<X509Certificate>>()

    /** The attest key's public half, for the console's key panel and the trace. */
    val attestKeyPublic: ECKey = attestKey.toPublicJWK()

    /** Generates a device key inside the WSCD, attested by the attest key. */
    fun generateKey(id: String): ECKey = attest(WalletKeys.generateKey(id), KeyDescription.ORIGIN_GENERATED)

    /**
     * Imports [key], made outside the WSCD, and attests it with the attest key, as KeyMint's
     * importKey does when given an attestation key: the certificate is signed by the same attest
     * key, but records origin IMPORTED, or SECURELY_IMPORTED for a wrapped import.
     */
    fun importKey(key: ECKey, securelyWrapped: Boolean = false): ECKey = attest(
        key,
        if (securelyWrapped) KeyDescription.ORIGIN_SECURELY_IMPORTED else KeyDescription.ORIGIN_IMPORTED,
    )

    private fun attest(key: ECKey, origin: Int): ECKey {
        val leaf = issueCertificate(
            subject = KEYSTORE_SUBJECT,
            publicKey = key.toPublicKey(),
            issuer = X500Name.getInstance(attestKeyCertificate.subjectX500Principal.encoded),
            signingKey = attestKey,
            validUntil = KEYSTORE_NOT_AFTER,
            description = description(setOf(KeyDescription.PURPOSE_SIGN), origin),
        )
        chains[key.computeThumbprint().toString()] = listOf(leaf, attestKeyCertificate) + batchChain
        return key
    }

    private fun description(purposes: Set<Int>, origin: Int) = KeyDescription(
        securityLevel = KeyDescription.SECURITY_LEVEL_STRONGBOX,
        challenge = challenge(),
        purposes = purposes,
        origin = origin,
        rootOfTrust = rootOfTrust,
        applicationId = app,
    )

    /** The attestation chain (key, attest key, batch, root) of a key generated here, or null. */
    fun attestationChain(key: ECKey): List<X509Certificate>? = chains[key.computeThumbprint().toString()]

    private fun challenge(): ByteArray = ByteArray(16).also { random.nextBytes(it) }

    private companion object {
        /** Android Keystore puts this subject on every key certificate, attest keys included. */
        val KEYSTORE_SUBJECT = X500Name("CN=Android Keystore Key")

        /** Android Keystore key certificates run to 2048 unless the app sets a validity. */
        val KEYSTORE_NOT_AFTER: Instant = ZonedDateTime.of(2048, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant()
    }
}

/** An X.509 certificate over [publicKey], signed by [signingKey], optionally carrying a [description]. */
internal fun issueCertificate(
    subject: X500Name,
    publicKey: PublicKey,
    issuer: X500Name,
    signingKey: ECKey,
    validUntil: Instant,
    description: KeyDescription? = null,
    ca: Boolean = false,
): X509Certificate {
    val now = Instant.now()
    val builder = JcaX509v3CertificateBuilder(
        issuer,
        BigInteger(64, SecureRandom()),
        Date.from(now.minusSeconds(60)),
        Date.from(validUntil),
        subject,
        publicKey,
    )
    if (description != null) builder.addExtension(ASN1ObjectIdentifier(KeyDescription.OID), false, description.toAsn1())
    if (ca) builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
    val signer = JcaContentSignerBuilder("SHA256withECDSA").build(signingKey.toPrivateKey())
    return JcaX509CertificateConverter().getCertificate(builder.build(signer))
}
