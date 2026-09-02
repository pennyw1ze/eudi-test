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
    /** Which stored credential to present. Defaults to the most recent SD-JWT VC. */
    val credentialId: String? = null,
    /** A DCQL query for the verifier to ask. Defaults to a couple of PID claims. */
    val dcqlQuery: JsonObject? = null,
)

@Serializable
data class PresentationResult(
    val flowId: String,
    val status: String,
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
    private val store: CredentialStore,
    private val keys: WalletKeys,
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
        val client = tracedHttpClient(flowId, sink)

        return try {
            sink.step(flowId, "Starting OpenID4VP presentation")

            val credential = pickCredential(request)
            val query = request.dcqlQuery ?: VerifierDriver.defaultDcqlQuery()
            val nonce = UUID.randomUUID().toString()

            val transaction = verifier.initTransaction(client, flowId, query, nonce)
            val requestUri = verifier.authorizationRequestUri(transaction)

            sink.step(flowId, "Wallet received an authorisation request by reference")
            val openId4Vp = OpenId4Vp.overRedirects(config, client)

            val resolution = openId4Vp.resolveRequestUri(requestUri)
            val resolved = when (resolution) {
                is Resolution.Success -> resolution.requestObject
                is Resolution.Invalid -> error("Wallet rejected the request: ${resolution.error}")
            }

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

            val walletResponse = verifier.walletResponse(client, flowId, transaction.transactionId)

            PresentationResult(
                flowId = flowId,
                status = "presented",
                transactionId = transaction.transactionId,
                authorizationRequestUri = requestUri,
                requestedClaims = requestedPaths.map { it.toString() },
                presentedCredentialId = credential.id,
                walletResponse = walletResponse,
            )
        } catch (failure: Exception) {
            sink.error(flowId, failure.message ?: failure.toString())
            PresentationResult(flowId = flowId, status = "failed", error = failure.message ?: failure.toString())
        } finally {
            client.close()
        }
    }

    private fun pickCredential(request: PresentationRequest): StoredCredential {
        request.credentialId?.let { id ->
            return store.get(id) ?: error("No stored credential with id '$id'")
        }
        return store.all().lastOrNull { it.format.contains("sd-jwt") }
            ?: error("The wallet holds no SD-JWT VC credential; issue one first")
    }

    /**
     * Produces the vp_token: the issuer-signed SD-JWT, the disclosures the verifier
     * asked for, and a key binding JWT tying the presentation to this verifier,
     * this nonce, and the wallet's device key.
     */
    private suspend fun buildSdJwtPresentation(
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
            signer = ECDSASigner(keys.deviceKey),
            signAlgorithm = JWSAlgorithm.ES256,
            publicKey = keys.deviceKey.toPublicJWK(),
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
