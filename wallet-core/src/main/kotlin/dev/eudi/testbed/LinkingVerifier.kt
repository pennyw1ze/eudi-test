package dev.eudi.testbed

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.Serializable

/**
 * The verifier's verdict on the link credential — steps 3 and 4 of the paper's verifier
 * procedure, reported alongside the ordinary presentation outcome.
 */
@Serializable
data class LinkVerdict(
    /** Whether a link credential was asked for at all (i.e. this was a linkable presentation). */
    val requested: Boolean = false,
    /** Whether the linking issuer certified co-residency and issued a link credential. */
    val issued: Boolean = false,
    /** Whether the verifier's link check passed. */
    val accepted: Boolean = false,
    val reason: String? = null,
    /** Keys the link credential covers. */
    val linkedKeyThumbprints: List<String> = emptyList(),
    /** The `cnf` keys the verifier read off the presented credentials. */
    val presentedKeyThumbprints: List<String> = emptyList(),
    val linkingIssuer: String? = null,
)

/**
 * The verifier-side extension that adds pooling resistance without changing what the
 * reference verifier already does (paper "Verifier patch: an extension to a reference
 * verifier adding steps 3 and 4"). The reference verifier still checks the issuer
 * signatures, the disclosures, both key-binding (device) signatures and revocation
 * (steps 1, 2, 5, 6). This adds:
 *
 *   step 3 — verify the linking issuer's signature on the link credential, against the
 *            linking issuer's key on a trusted list;
 *   step 4 — check the link credential's contents equal exactly the set of `cnf` keys
 *            carried by the presented credentials.
 *
 * A pooled presentation fails step 3 already, because the linking issuer refused to
 * certify two cross-WSCD keys and there is no valid link credential to check. A single
 * holder's genuine two-credential presentation passes both.
 *
 * The verifier evaluates a relation on the two presented keys — "a link credential
 * exists over exactly this pair" — but the relation is only decidable given the
 * credential, so colluding verifiers holding two keys from separate sessions cannot
 * evaluate it (paper Prop. "escape"); verifier unlinkability is preserved.
 */
class LinkingVerifier(
    trustedLinkingKeys: List<ECKey>,
    private val crypto: CryptoSink,
) {
    private val trustedThumbprints: Set<String> =
        trustedLinkingKeys.map { it.toPublicJWK().computeThumbprint().toString() }.toSet()

    fun verify(
        presentedKeys: List<ECKey>,
        link: LinkResult,
        flowId: String,
        walletUnitId: String? = null,
    ): LinkVerdict {
        // Compared as a set: two of a holder's credentials may be bound to the same device
        // key (single, non-batch issuance), so the presented list can carry a key twice.
        // What must match is the *set* of keys the link credential covers.
        val presentedThumbprints = presentedKeys.map { it.computeThumbprint().toString() }.distinct().sorted()

        fun reject(reason: String, linkingIssuer: String? = null, linked: List<String> = emptyList()): LinkVerdict {
            crypto.record(
                flowId = flowId,
                operation = "verify",
                actor = "verifier",
                artifact = "Link credential",
                summary = "Verifier rejected the presentation on the pooling check: $reason",
                binds = buildMap {
                    put("reason", reason)
                    put("presented keys", presentedThumbprints.joinToString(", "))
                    if (linked.isNotEmpty()) put("linked keys", linked.joinToString(", "))
                },
                caveat = "Step 3/4 of the countermeasure. Without a link credential over exactly the " +
                    "presented keys, the verifier cannot conclude the credentials belong to one holder, " +
                    "so it rejects — this is where a pooled presentation is caught.",
                walletUnitId = walletUnitId,
            )
            return LinkVerdict(
                requested = true,
                issued = link.issued,
                accepted = false,
                reason = reason,
                linkedKeyThumbprints = linked,
                presentedKeyThumbprints = presentedThumbprints,
                linkingIssuer = linkingIssuer,
            )
        }

        if (!link.issued || link.credential == null) {
            return reject(
                "no link credential over the presented keys" +
                    (link.reason?.let { " (linking issuer: $it)" } ?: ""),
            )
        }

        val jws = runCatching { SignedJWT.parse(link.credential) }.getOrNull()
            ?: return reject("the link credential is unparseable")

        val signer = jws.x5cLeafKey()
            ?: return reject("the link credential carried no usable linking-issuer certificate")
        val signerThumbprint = signer.computeThumbprint().toString()

        if (signerThumbprint !in trustedThumbprints) {
            return reject("the link credential was not issued by a trusted linking issuer")
        }
        if (!jws.verifiedBy(signer)) {
            return reject("the link credential's signature did not verify")
        }

        val issuer = runCatching { jws.jwtClaimsSet.issuer }.getOrNull()
        val linked = runCatching { jws.jwtClaimsSet.getStringListClaim("linked_key_thumbprints") }
            .getOrNull()
            .orEmpty()
            .sorted()

        if (linked != presentedThumbprints) {
            return reject(
                "the link credential does not cover exactly the presented keys",
                linkingIssuer = issuer,
                linked = linked,
            )
        }

        crypto.record(
            flowId = flowId,
            operation = "verify",
            actor = "verifier",
            artifact = "Link credential",
            summary = "Verifier accepted the pooling check: a trusted linking issuer certified that the " +
                "${presentedThumbprints.size} presented credentials' keys are co-resident in one WSCD",
            keys = presentedKeys.map { it.asLinkedKeyRef() },
            binds = mapOf(
                "linking issuer" to (issuer ?: "unknown"),
                "linked keys" to linked.joinToString(", "),
            ),
            walletUnitId = walletUnitId,
        )

        return LinkVerdict(
            requested = true,
            issued = true,
            accepted = true,
            reason = null,
            linkedKeyThumbprints = linked,
            presentedKeyThumbprints = presentedThumbprints,
            linkingIssuer = issuer,
        )
    }
}
