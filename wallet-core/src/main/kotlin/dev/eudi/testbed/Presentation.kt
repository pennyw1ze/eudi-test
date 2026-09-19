package dev.eudi.testbed

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.dcql.CredentialQuery
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
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

/**
 * A *pooled* presentation: two (or more) colluding wallet units jointly answer one
 * verifier request, each contributing a credential held by a different unit and each
 * signing its own key binding JWT with its own device key.
 *
 * This is Attack A (presentation-time relay pooling) from the paper. It is meaningful
 * only against a verifier that binds credentials to a holder *presentationally* — by
 * asking one wallet to return everything over one nonce — rather than proving the
 * several credentials share a subject. The reference verifier does exactly that, so a
 * response carrying two credentials under two different device keys passes every check.
 */
@Serializable
data class PooledPresentationRequest(
    /**
     * The colluding wallet units, in the order they are searched to answer each
     * credential query. The first unit is the "front": it drives the OpenID4VP
     * exchange and posts the combined vp_token; the others hand it a key binding JWT
     * over the shared nonce for the credential they hold.
     */
    val walletUnitIds: List<String> = emptyList(),
    val verifierId: String? = null,
    /** The DCQL query the verifier asks. For a pool this normally lists several credentials. */
    val dcqlQuery: JsonObject? = null,
)

/** One wallet unit's contribution to a pooled presentation: which query it answered, and with which key. */
@Serializable
data class PooledContribution(
    val queryId: String,
    val walletUnitId: String,
    val walletUnitLabel: String,
    val credentialId: String,
    val vct: String? = null,
    /** RFC 7638 thumbprint of the device key that signed this credential's key binding JWT. */
    val deviceKeyThumbprint: String,
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
    /** Every credential presented, one per credential query the verifier asked for. */
    val presentedCredentialIds: List<String> = emptyList(),
    val walletResponse: JsonElement? = null,
    val error: String? = null,
    /** True when more than one wallet unit contributed a credential (the pooling attack). */
    val pooled: Boolean = false,
    /** Who signed what, when the presentation was pooled across units. */
    val contributions: List<PooledContribution> = emptyList(),
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

    /** One wallet unit's answer to one credential query: the credential and the key that will sign its binding. */
    private data class Contribution(
        val unit: WalletUnit,
        val credential: StoredCredential,
        val boundKey: ECKey,
    )

    /**
     * Ordinary single-holder presentation: one wallet unit answers every credential
     * query in the request with credentials it holds, all under its own device key(s).
     */
    suspend fun present(request: PresentationRequest): PresentationResult {
        val flowId = "vp-${UUID.randomUUID().toString().take(8)}"
        val unit = registry.walletUnit(request.walletUnitId)
        val verifierRef = registry.verifier(request.verifierId)
        val query = request.dcqlQuery ?: VerifierDriver.defaultDcqlQuery()

        sink.step(flowId, "Starting OpenID4VP presentation from '${unit.label}' to '${verifierRef.label}'")

        return runExchange(flowId, leadUnit = unit, verifierRef = verifierRef, query = query, pooled = false) { credentialQuery, queryCount ->
            val wantedVcts = credentialQuery.vctValues()
            matchCredential(credentialQuery, wantedVcts, unit, request, queryCount)
        }
    }

    /**
     * Pooled presentation (Attack A): several colluding wallet units jointly answer one
     * request. Each credential query is routed to whichever unit holds a matching
     * credential, and that unit's own device key signs its key binding JWT. The front
     * unit posts the combined vp_token; from the verifier's side it is one response.
     */
    suspend fun presentPooled(request: PooledPresentationRequest): PresentationResult {
        val flowId = "vp-${UUID.randomUUID().toString().take(8)}"
        val units = request.walletUnitIds
            .ifEmpty { registry.walletUnits().map { it.id } }
            .map { registry.walletUnit(it) }
            .distinctBy { it.id }
        if (units.size < 2) {
            error("A pooled presentation needs at least two distinct wallet units; got ${units.size}")
        }
        val leadUnit = units.first()
        val verifierRef = registry.verifier(request.verifierId)
        val query = request.dcqlQuery ?: VerifierDriver.defaultDcqlQuery()

        sink.step(
            flowId,
            "Starting POOLED OpenID4VP presentation to '${verifierRef.label}' across ${units.size} colluding units: " +
                units.joinToString(", ") { "'${it.label}'" },
        )

        return runExchange(flowId, leadUnit = leadUnit, verifierRef = verifierRef, query = query, pooled = true) { credentialQuery, _ ->
            val wantedVcts = credentialQuery.vctValues()
            matchAcrossUnits(credentialQuery, wantedVcts, units)
        }
    }

    /**
     * The shared OpenID4VP exchange. [resolve] decides, per credential query, which unit
     * and credential answer it and with which key its binding is signed — the only thing
     * that differs between a single-holder and a pooled presentation.
     */
    private suspend fun runExchange(
        flowId: String,
        leadUnit: WalletUnit,
        verifierRef: VerifierRef,
        query: JsonObject,
        pooled: Boolean,
        resolve: (CredentialQuery, Int) -> Contribution,
    ): PresentationResult {
        val client = tracedHttpClient(flowId, sink, scanner = scanner, walletUnitId = leadUnit.id)

        return try {
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
                        walletUnitId = leadUnit.id,
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
                walletUnitId = leadUnit.id,
            )

            // A combined presentation (ARF 6.6.3.10) carries several credential queries in
            // one request. OpenID4VP answers each with its own entry in the vp_token,
            // keyed by the query id, and each SD-JWT VC carries its own key binding JWT
            // over the same nonce and audience. In a pooled presentation the entries are
            // signed by *different* units' device keys — that is the attack.
            val credentialQueries = resolved.query.credentials.value
            if (credentialQueries.isEmpty()) error("The verifier's DCQL query contains no credential queries")

            val presented = credentialQueries.map { credentialQuery ->
                if (credentialQuery.format.value.contains("mdoc")) {
                    error(
                        "Credential query '${credentialQuery.id.value}' asks for mso_mdoc; " +
                            "the testbed can only present SD-JWT VC so far",
                    )
                }
                val wantedVcts = credentialQuery.vctValues()
                val contribution = resolve(credentialQuery, credentialQueries.size)
                val requestedPaths = credentialQuery.claims.orEmpty().map { it.path }
                sink.step(
                    flowId,
                    "Verifier '${resolved.client.id.clientId}' asks credential '${credentialQuery.id.value}'" +
                        (wantedVcts.firstOrNull()?.let { " ($it)" } ?: "") + " for: " +
                        (requestedPaths.joinToString(", ").ifBlank { "all claims" }),
                    actor = "verifier",
                )
                if (pooled) {
                    sink.step(
                        flowId,
                        "Pooled: unit '${contribution.unit.label}' answers query '${credentialQuery.id.value}' " +
                            "with its own credential and signs the key binding with its own device key",
                    )
                    // The crux of Attack A made explicit in the crypto trace: this entry's
                    // key binding is signed by a device key that belongs to a *different*
                    // unit than the one signing the other entry, yet the verifier treats
                    // the response as coming from one holder.
                    crypto.record(
                        flowId = flowId,
                        operation = "sign",
                        actor = "wallet",
                        artifact = "Key binding JWT for query '${credentialQuery.id.value}'",
                        summary = "Wallet unit '${contribution.unit.label}' signed the key binding for its " +
                            "own credential, over the verifier's shared nonce and audience",
                        algorithm = "ES256",
                        keys = listOf(contribution.boundKey.asDeviceKeyRef()),
                        binds = mapOf(
                            "credential" to contribution.credential.id,
                            "nonce" to resolved.nonce,
                            "audience" to resolved.client.id.clientId,
                        ),
                        caveat = "This key binding is signed by a device key held by a different wallet unit " +
                            "than the one signing the other credential in the same vp_token. The verifier " +
                            "binds credentials to a holder presentationally (one nonce, one response), so it " +
                            "cannot tell that two devices — two people — jointly produced this response.",
                        walletUnitId = contribution.unit.id,
                    )
                }
                // Batch-issued copies each bind to a distinct key, so the key-binding JWT
                // must be signed by the key this specific copy was bound to. Fall back to
                // the unit's device key for credentials issued before per-credential keys
                // were tracked (single, non-batch issuance).
                val vpToken = buildSdJwtPresentation(
                    deviceKey = contribution.boundKey,
                    raw = contribution.credential.raw,
                    requestedPaths = requestedPaths,
                    audience = resolved.client.id.clientId,
                    nonce = resolved.nonce,
                )
                Presented(credentialQuery.id, contribution, requestedPaths, vpToken) to credentialQuery
            }

            sink.step(
                flowId,
                "Wallet posts a vp_token with ${presented.size} presentation(s) to the verifier" +
                    if (pooled) " (pooled across ${presented.map { it.first.contribution.unit.id }.distinct().size} units)" else "",
            )
            val consensus = Consensus.PositiveConsensus(
                VerifiablePresentations(
                    presented.associate { (p, _) ->
                        p.queryId to listOf(VerifiablePresentation.Generic(p.vpToken))
                    },
                ),
            )

            val requestedPaths = presented.flatMap { (p, _) -> p.requestedPaths }
            val presentedCredentials = presented.map { (p, _) -> p.contribution.credential }

            val outcome = openId4Vp.dispatch(resolved, consensus, encryptionParameters = null)
            sink.step(flowId, "Verifier responded: $outcome", actor = "verifier")

            // A rejected vp_token is a failed presentation. Reporting it as success
            // because the exchange completed would hide exactly what we came to test.
            val accepted = outcome !is DispatchOutcome.VerifierResponse.Rejected
            val rejection = if (accepted) null else rejectionReason(flowId)

            val contributions = presented.map { (p, credentialQuery) ->
                PooledContribution(
                    queryId = p.queryId.value,
                    walletUnitId = p.contribution.unit.id,
                    walletUnitLabel = p.contribution.unit.label,
                    credentialId = p.contribution.credential.id,
                    vct = credentialQuery.vctValues().firstOrNull() ?: vctOf(p.contribution.credential.raw),
                    deviceKeyThumbprint = p.contribution.boundKey.computeThumbprint().toString(),
                )
            }
            val distinctUnits = contributions.map { it.walletUnitId }.distinct().size

            // The verdict is the last cryptographic act of the exchange: the verifier
            // checked the issuer's signature, the disclosure digests and the key binding.
            crypto.record(
                flowId = flowId,
                operation = "verify",
                actor = "verifier",
                artifact = "Verifiable presentation",
                summary = if (accepted) {
                    "Verifier accepted the presentation: the issuer's signature, the digests of the " +
                        "disclosed claims and the key binding to this nonce all checked out" +
                        if (pooled && distinctUnits > 1) {
                            " — even though the $distinctUnits credentials were signed by $distinctUnits " +
                                "different device keys from $distinctUnits different wallet units (Attack A)"
                        } else {
                            ""
                        }
                } else {
                    "Verifier rejected the presentation"
                },
                binds = buildMap { rejection?.let { put("reason", it) } },
                walletUnitId = leadUnit.id,
            )

            val walletResponse = verifier.walletResponse(client, flowId, transaction.transactionId, verifierRef)

            PresentationResult(
                flowId = flowId,
                status = if (accepted) "presented" else "rejected",
                walletUnitId = leadUnit.id,
                error = if (accepted) null else "The verifier rejected the vp_token: ${rejection ?: "no reason given"}",
                transactionId = transaction.transactionId,
                authorizationRequestUri = requestUri,
                requestedClaims = requestedPaths.map { it.toString() },
                presentedCredentialId = presentedCredentials.firstOrNull()?.id,
                presentedCredentialIds = presentedCredentials.map { it.id },
                walletResponse = walletResponse,
                pooled = pooled && distinctUnits > 1,
                contributions = if (pooled) contributions else emptyList(),
            )
        } catch (failure: Exception) {
            sink.error(flowId, failure.message ?: failure.toString())
            PresentationResult(
                flowId = flowId,
                status = "failed",
                walletUnitId = leadUnit.id,
                error = failure.message ?: failure.toString(),
                pooled = pooled,
            )
        } finally {
            client.close()
        }
    }

    /** One credential query's resolved answer, carried alongside the vp_token it produced. */
    private data class Presented(
        val queryId: QueryId,
        val contribution: Contribution,
        val requestedPaths: List<DcqlClaimPath>,
        val vpToken: String,
    )

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

    /** The vct values a credential query asks for, read from its raw DCQL meta. */
    private fun CredentialQuery.vctValues(): List<String> =
        (meta?.get("vct_values") as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            .orEmpty()

    /** The vct of a stored SD-JWT VC, read from the issuer-signed JWT payload. */
    private fun vctOf(raw: String): String? = runCatching {
        val payload = raw.substringBefore('~').split('.')[1]
        Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(payload)))
            .jsonObject["vct"]?.jsonPrimitive?.contentOrNull
    }.getOrNull()

    /** A public [KeyRef] for a device key, so the console can colour it in the crypto trace. */
    private fun ECKey.asDeviceKeyRef(): KeyRef = KeyRef(
        role = "device",
        thumbprint = computeThumbprint().toString(),
        kty = keyType.value,
        crv = curve.name,
        kid = keyID,
        storage = "software (JVM heap)",
    )

    /**
     * Pick the held credential that answers one credential query.
     *
     * Matching is by vct, because a combined request usually asks for several
     * `dc+sd-jwt` credentials and matching on format alone would present the wrong one.
     * An explicit credentialId is honoured only for a single-credential request, where
     * it is unambiguous.
     */
    private fun matchCredential(
        query: CredentialQuery,
        wantedVcts: List<String>,
        unit: WalletUnit,
        request: PresentationRequest,
        queryCount: Int,
    ): Contribution {
        if (queryCount == 1) {
            request.credentialId?.let { id ->
                // Deliberately scoped to this unit: asking one unit to present another's
                // credential is exactly the mistake the device key binding exists to catch.
                val credential = unit.store.get(id)
                    ?: error("Wallet unit '${unit.label}' holds no credential with id '$id'")
                val boundKey = unit.store.deviceKeyFor(credential.id) ?: unit.keys.deviceKey
                return Contribution(unit, credential, boundKey)
            }
        }
        val sdJwts = unit.store.all().filter { it.format.contains("sd-jwt") || it.raw.contains('~') }
        val match =
            if (wantedVcts.isEmpty()) sdJwts.lastOrNull()
            else sdJwts.lastOrNull { vctOf(it.raw) in wantedVcts }
        val credential = match ?: error(
            "Wallet unit '${unit.label}' holds no SD-JWT VC for query '${query.id.value}'" +
                (wantedVcts.firstOrNull()?.let { " (vct $it)" } ?: "") + "; issue one first",
        )
        val boundKey = unit.store.deviceKeyFor(credential.id) ?: unit.keys.deviceKey
        return Contribution(unit, credential, boundKey)
    }

    /**
     * Route one credential query to whichever pooled unit holds a matching credential.
     *
     * Units are searched in order and the first match wins, so distinct-vct queries in a
     * combined request naturally fall to the units that hold each vct — which is what
     * makes the presentation genuinely pooled. A unit's copy is bound to its own device
     * key, and that key signs the key binding, so no key is shared across the pool.
     */
    private fun matchAcrossUnits(
        query: CredentialQuery,
        wantedVcts: List<String>,
        units: List<WalletUnit>,
    ): Contribution {
        for (unit in units) {
            val sdJwts = unit.store.all().filter { it.format.contains("sd-jwt") || it.raw.contains('~') }
            val match =
                if (wantedVcts.isEmpty()) sdJwts.lastOrNull()
                else sdJwts.lastOrNull { vctOf(it.raw) in wantedVcts }
            if (match != null) {
                val boundKey = unit.store.deviceKeyFor(match.id) ?: unit.keys.deviceKey
                return Contribution(unit, match, boundKey)
            }
        }
        error(
            "None of the pooled wallet units holds an SD-JWT VC for query '${query.id.value}'" +
                (wantedVcts.firstOrNull()?.let { " (vct $it)" } ?: "") + "; issue one first",
        )
    }

    /**
     * Produces the vp_token: the issuer-signed SD-JWT, the disclosures the verifier
     * asked for, and a key binding JWT tying the presentation to this verifier,
     * this nonce, and the wallet's device key.
     */
    private suspend fun buildSdJwtPresentation(
        deviceKey: ECKey,
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
            signer = ECDSASigner(deviceKey),
            signAlgorithm = JWSAlgorithm.ES256,
            publicKey = deviceKey.toPublicJWK(),
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
