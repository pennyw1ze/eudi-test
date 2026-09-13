package dev.eudi.testbed

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.dcql.CredentialQuery
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.util.Date
import java.util.UUID
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPath as DcqlClaimPath
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPathElement as DcqlClaimPathElement
import eu.europa.ec.eudi.sdjwt.vc.ClaimPath as SdJwtClaimPath
import eu.europa.ec.eudi.sdjwt.vc.ClaimPathElement as SdJwtClaimPathElement

@Serializable
data class PresentationRequest(
    /** Which wallet unit presents. Defaults to the first one. */
    val walletUnitId: String? = null,
    /** Which registered verifier acts as relying party. Defaults to the first one. */
    val verifierId: String? = null,
    /** Which stored credential to present. Defaults to the most recent SD-JWT VC. */
    val credentialId: String? = null,
    /** A DCQL query for the verifier to ask. Defaults to a couple of PID claims. */
    val dcqlQuery: JsonObject? = null,
)

@Serializable
data class PresentationResult(
    val flowId: String,
    val status: String,
    val walletUnitId: String? = null,
    val transactionId: String? = null,
    val authorizationRequestUri: String? = null,
    /** Claims the verifier asked for, as the wallet understood them. */
    val requestedClaims: List<String> = emptyList(),
    val presentedCredentialId: String? = null,
    val walletResponse: JsonElement? = null,
    val error: String? = null,
)

/**
 * Drives OpenID4VP in the wallet (holder) role using the official
 * `eudi-lib-jvm-openid4vp-kt` library, against the reference verifier.
 *
 * Only SD-JWT VC is presented. Presenting an `mso_mdoc` credential means assembling a
 * signed DeviceResponse over a session transcript, which this testbed does not build
 * yet; such a request is reported rather than silently skipped.
 */
class PresentationService(
    private val sink: TraceSink,
    private val crypto: CryptoSink,
    private val scanner: CryptoScanner,
    private val registry: Registry,
    private val verifier: VerifierDriver,
) {

    private val config = OpenId4VPConfig(
        vpFormatsSupported = VpFormatsSupported(sdJwtVc = VpFormatsSupported.SdJwtVc.HAIP),
        // The verifier signs its request with a certificate from its own test CA, so
        // chain validation is accepted wholesale here.
        supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.X509SanDns { _ -> true }),
    )

    suspend fun present(request: PresentationRequest): PresentationResult {
        val flowId = "vp-${UUID.randomUUID().toString().take(8)}"
        val unit = registry.walletUnit(request.walletUnitId)
        val verifierRef = registry.verifier(request.verifierId)
        val client = tracedHttpClient(flowId, sink, scanner = scanner, walletUnitId = unit.id)

        return try {
            sink.step(flowId, "Starting OpenID4VP presentation from '${unit.label}' to '${verifierRef.label}'")

            val credential = pickCredential(request, unit)
            val query = request.dcqlQuery ?: VerifierDriver.defaultDcqlQuery()
            val nonce = UUID.randomUUID().toString()

            val transaction = verifier.initTransaction(client, flowId, query, nonce, verifierRef)
            val requestUri = verifier.authorizationRequestUri(transaction)

            sink.step(flowId, "Wallet received an authorisation request by reference")
            val openId4Vp = OpenId4Vp.overRedirects(config, client)

            val resolution = openId4Vp.resolveRequestUri(requestUri)
            val resolved = when (resolution) {
                is Resolution.Success -> resolution.requestObject
                is Resolution.Invalid -> {
                    // A rejected request object never produces a presentation, and the reason
                    // is cryptographic; it belongs in the crypto trace, not only in the error.
                    crypto.record(
                        flowId = flowId,
                        operation = "verify",
                        actor = "wallet",
                        artifact = "Authorisation request object (JAR)",
                        summary = "Wallet rejected the verifier's signed request",
                        binds = mapOf("reason" to resolution.error.toString()),
                        walletUnitId = unit.id,
                    )
                    error("Wallet rejected the request: ${resolution.error}")
                }
            }

            // Accepting the request is itself a cryptographic decision, and it happens
            // inside the wallet, so no exchange on the wire records it.
            crypto.record(
                flowId = flowId,
                operation = "verify",
                actor = "wallet",
                artifact = "Authorisation request object (JAR)",
                summary = "Wallet verified the verifier's signature and accepted its identity " +
                    "before deciding what to disclose",
                keys = emptyList(),
                binds = mapOf(
                    "client id" to resolved.client.id.clientId,
                    "client id prefix" to resolved.client.id.prefix.toString(),
                    "nonce" to resolved.nonce,
                ),
                caveat = "The certificate chain is accepted wholesale: the testbed's X509SanDns " +
                    "trust check returns true for every chain. A real wallet would resolve the " +
                    "verifier against a trusted list of registered relying parties.",
                walletUnitId = unit.id,
            )

            val credentialQuery = resolved.query.credentials.value.firstOrNull()
                ?: error("The verifier's DCQL query contains no credential queries")

            if (credentialQuery.format.value.contains("mdoc")) {
                error("This request asks for mso_mdoc; the testbed can only present SD-JWT VC so far")
            }

            val requestedPaths = credentialQuery.claims.orEmpty().map { it.path }
            sink.step(
                flowId,
                "Verifier '${resolved.client.id.clientId}' asks for: " +
                    (requestedPaths.joinToString(", ").ifBlank { "all claims" }),
                actor = "verifier",
            )

            val vpToken = buildSdJwtPresentation(
                unit = unit,
                raw = credential.raw,
                requestedPaths = requestedPaths,
                audience = resolved.client.id.clientId,
                nonce = resolved.nonce,
            )

            sink.step(flowId, "Wallet posts the vp_token to the verifier's response endpoint")
            val consensus = Consensus.PositiveConsensus(
                VerifiablePresentations(
                    mapOf(credentialQuery.id to listOf(VerifiablePresentation.Generic(vpToken))),
                ),
            )

            val outcome = openId4Vp.dispatch(resolved, consensus, encryptionParameters = null)
            sink.step(flowId, "Verifier responded: $outcome", actor = "verifier")

            // A rejected vp_token is a failed presentation. Reporting it as success
            // because the exchange completed would hide exactly what we came to test.
            val accepted = outcome !is DispatchOutcome.VerifierResponse.Rejected
            val rejection = if (accepted) null else rejectionReason(flowId)

            // The verdict is the last cryptographic act of the exchange: the verifier
            // checked the issuer's signature, the disclosure digests and the key binding.
            crypto.record(
                flowId = flowId,
                operation = "verify",
                actor = "verifier",
                artifact = "Verifiable presentation",
                summary = if (accepted) {
                    "Verifier accepted the presentation: the issuer's signature, the digests of the " +
                        "disclosed claims and the key binding to this nonce all checked out"
                } else {
                    "Verifier rejected the presentation"
                },
                binds = buildMap { rejection?.let { put("reason", it) } },
                walletUnitId = unit.id,
            )

            val walletResponse = verifier.walletResponse(client, flowId, transaction.transactionId, verifierRef)

            PresentationResult(
                flowId = flowId,
                status = if (accepted) "presented" else "rejected",
                walletUnitId = unit.id,
                error = if (accepted) null else "The verifier rejected the vp_token: ${rejection ?: "no reason given"}",
                transactionId = transaction.transactionId,
                authorizationRequestUri = requestUri,
                requestedClaims = requestedPaths.map { it.toString() },
                presentedCredentialId = credential.id,
                walletResponse = walletResponse,
            )
        } catch (failure: Exception) {
            sink.error(flowId, failure.message ?: failure.toString())
            PresentationResult(
                flowId = flowId,
                status = "failed",
                walletUnitId = unit.id,
                error = failure.message ?: failure.toString(),
            )
        } finally {
            client.close()
        }
    }

    /**
     * The verifier's own words for a rejection.
     *
     * `DispatchOutcome.VerifierResponse.Rejected` is a singleton carrying no detail, so
     * the reason survives only in the response body the tracer captured. Recovering it
     * is the difference between "see the protocol log" and an answer — which is exactly
     * the difference that hid the 20-second validity window for as long as it did.
     */
    private fun rejectionReason(flowId: String): String? =
        sink.since(0, flowId)
            .lastOrNull { it.kind == "http" && (it.status ?: 0) >= 400 && !it.responseBody.isNullOrBlank() }
            ?.responseBody
            ?.trim()
            ?.take(400)

    private fun pickCredential(request: PresentationRequest, unit: WalletUnit): StoredCredential {
        request.credentialId?.let { id ->
            // Deliberately scoped to this unit: asking one unit to present another's
            // credential is exactly the mistake the device key binding exists to catch.
            return unit.store.get(id)
                ?: error("Wallet unit '${unit.label}' holds no credential with id '$id'")
        }
        return unit.store.all().lastOrNull { it.format.contains("sd-jwt") }
            ?: error("Wallet unit '${unit.label}' holds no SD-JWT VC credential; issue one first")
    }

    /**
     * Produces the vp_token: the issuer-signed SD-JWT, the disclosures the verifier
     * asked for, and a key binding JWT tying the presentation to this verifier,
     * this nonce, and the wallet's device key.
     */
    private suspend fun buildSdJwtPresentation(
        unit: WalletUnit,
        raw: String,
        requestedPaths: List<DcqlClaimPath>,
        audience: String,
        nonce: String,
    // DefaultSdJwtOps is the operations bundle that can parse an unverified SD-JWT;
    // NimbusSdJwtOps only contributes the key binding JWT builder, which is not tied
    // to a JWT representation.
    ): String = with(DefaultSdJwtOps) {
        val issued = unverifiedIssuanceFrom(raw).getOrThrow()

        // An empty query means "disclose everything".
        val query = requestedPaths.mapNotNull { it.toSdJwt() }.toSet()
        val presentation = issued.present(query)
            ?: error("The stored credential cannot satisfy the requested claims")

        val buildKbJwt = NimbusSdJwtOps.kbJwtIssuer(
            signer = ECDSASigner(unit.keys.deviceKey),
            signAlgorithm = JWSAlgorithm.ES256,
            publicKey = unit.keys.deviceKey.toPublicJWK(),
        ) {
            audience(audience)
            claim("nonce", nonce)
            issueTime(Date())
        }

        presentation.serializeWithKeyBinding(buildKbJwt).getOrThrow()
    }

    /** The two libraries model claim paths identically but in separate types. */
    private fun DcqlClaimPath.toSdJwt(): SdJwtClaimPath? {
        val elements = value.map { element ->
            when (element) {
                is DcqlClaimPathElement.Claim -> SdJwtClaimPathElement.Claim(element.name)
                is DcqlClaimPathElement.ArrayElement -> SdJwtClaimPathElement.ArrayElement(element.index)
                DcqlClaimPathElement.AllArrayElements -> SdJwtClaimPathElement.AllArrayElements
            }
        }
        val head = elements.firstOrNull() ?: return null
        return SdJwtClaimPath(head, *elements.drop(1).toTypedArray())
    }

    /** Exposed so the console can show what a credential query is asking for. */
    fun describe(query: CredentialQuery): String =
        "${query.id.value} (${query.format.value})"

    private val QueryId.asKey: String get() = value
}
