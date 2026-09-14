package dev.eudi.testbed

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

@Serializable
data class IssuanceRequest(
    /** Which wallet unit receives the credential. Defaults to the first one. */
    val walletUnitId: String? = null,
    /** Which registered issuer to ask. Defaults to the first one. */
    val issuerId: String? = null,
    /** A credential offer URI, if you already have one. */
    val offerUri: String? = null,
    /** Otherwise, ask the issuer directly for this configuration (wallet-initiated). */
    val credentialConfigurationId: String? = null,
    /** Log in headlessly with the sample realm user instead of using a browser. */
    val autoLogin: Boolean = true,
    val username: String? = null,
    val password: String? = null,
    /**
     * How many copies of the credential to obtain in one issuance (batch issuance).
     * Each copy is bound to a distinct device key, so the batch shares no value a verifier
     * could correlate across presentations (paper C4 unlinkability). Defaults to 1.
     */
    val copies: Int = 1,
)

@Serializable
data class IssuanceResult(
    val flowId: String,
    val status: String,
    val walletUnitId: String? = null,
    val credentials: List<StoredCredential> = emptyList(),
    /** Set when [IssuanceRequest.autoLogin] is false and a browser has to take over. */
    val authorizationUrl: String? = null,
    val warnings: List<String> = emptyList(),
    val error: String? = null,
)

/**
 * Drives OpenID4VCI in the wallet (holder) role using the official
 * `eudi-lib-jvm-openid4vci-kt` library.
 */
class IssuanceService(
    private val sink: TraceSink,
    private val scanner: CryptoScanner,
    private val registry: Registry,
) {

    private val keyStorageStatus = KeyStorageStatusProvider(sink)

    /** Flows paused waiting for a browser redirect, keyed by OAuth state. */
    private data class Pending(
        val flowId: String,
        val unit: WalletUnit,
        val issuer: Issuer,
        val prepared: AuthorizationRequestPrepared,
        val configurationId: CredentialConfigurationIdentifier,
        val client: HttpClient,
        val copies: Int,
    )

    private val pending = ConcurrentHashMap<String, Pending>()

    /**
     * Built per flow rather than once, because attestation-based client authentication
     * needs the flow's traced HTTP client (to take a status list entry) and its flow id
     * (so the exchange lands in the right timeline).
     */
    private fun configFor(
        client: HttpClient,
        flowId: String,
        unit: WalletUnit,
        issuerRef: IssuerRef,
    ) = OpenId4VCIConfig(
        // The reference issuer requires attestation-based client authentication: its
        // credential endpoint reads client_status off the access token, and only the
        // ABCA flow puts it there.
        clientAuthentication = ClientAuthentication.AttestationBased(
            id = issuerRef.clientId,
            provisionClientAttestation = WalletProviderAttestation(
                keys = unit.keys,
                statusProvider = keyStorageStatus,
                client = client,
                flowId = flowId,
                sink = sink,
                clientId = issuerRef.clientId,
            ),
        ),
        authFlowRedirectionURI = URI.create(Env.redirectUri),
        encryptionSupportConfig = EncryptionSupportConfig(
            ecKeyCurve = com.nimbusds.jose.jwk.Curve.P_256,
            rcaKeySize = 2048,
            credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
        ),
        // The upstream realm runs Keycloak with the dpop feature on and the issuer sets
        // ISSUER_DPOP_REALM, so its token endpoint rejects requests without a DPoP proof.
        dPoPUsage = DPoPUsage.IfSupported(
            DPoPConfig(
                object : ProvisionDPoPSigner {
                    override val popAlgorithm: JwsAlgorithm = JwsAlgorithm("ES256")
                    override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> =
                        EcSigner(unit.keys.dpopKey, unit.keys.dpopKey.toPublicJWK())
                },
            ),
        ),
    )

    suspend fun issue(request: IssuanceRequest): IssuanceResult {
        val flowId = "iss-${UUID.randomUUID().toString().take(8)}"
        val unit = registry.walletUnit(request.walletUnitId)
        val issuerRef = registry.issuer(request.issuerId)
        val client = tracedHttpClient(flowId, sink, withCookies = true, scanner = scanner, walletUnitId = unit.id)

        return try {
            sink.step(flowId, "Starting OpenID4VCI issuance as '${unit.label}' against '${issuerRef.label}'")

            val (issuer, warnings) =
                negotiate(flowId, request, client, configFor(client, flowId, unit, issuerRef), issuerRef)
            val configurationId = chooseConfiguration(issuer, request)

            sink.step(
                flowId,
                "Issuer ${issuer.credentialOffer.credentialIssuerIdentifier.value} offers '${configurationId.value}'",
                actor = "issuer",
            )

            val prepared = with(issuer) { prepareAuthorizationRequest().getOrThrow() }
            val authorizationUrl = prepared.authorizationCodeURL.value.toString()

            if (!request.autoLogin) {
                pending[prepared.state] = Pending(flowId, unit, issuer, prepared, configurationId, client, request.copies)
                sink.step(flowId, "Waiting for the user to log in via the browser")
                return IssuanceResult(
                    flowId = flowId,
                    status = "awaiting-authorization",
                    walletUnitId = unit.id,
                    authorizationUrl = authorizationUrl,
                    warnings = warnings.map { it.toString() },
                )
            }

            // Which subject to authenticate as decides which PID the issuer returns, so
            // picking a different subject per wallet unit is how two units end up with
            // two distinct PIDs. The password follows from the chosen subject when it is
            // one of the known sample persons.
            val loginUser = request.username ?: issuerRef.loginUser
            val loginPassword = request.password ?: Env.passwordFor(loginUser) ?: issuerRef.loginPassword

            val callback = KeycloakLogin.authorize(
                client = client,
                authorizationUrl = authorizationUrl,
                username = loginUser,
                password = loginPassword,
                sink = sink,
                flowId = flowId,
            )

            val credentials = redeem(
                flowId = flowId,
                unit = unit,
                issuer = issuer,
                prepared = prepared,
                configurationId = configurationId,
                code = callback.code,
                serverState = callback.state ?: prepared.state,
                client = client,
                copies = request.copies,
            )

            IssuanceResult(
                flowId = flowId,
                status = "issued",
                walletUnitId = unit.id,
                credentials = credentials,
                warnings = warnings.map { it.toString() },
            )
        } catch (failure: Exception) {
            sink.error(flowId, failure.message ?: failure.toString())
            IssuanceResult(
                flowId = flowId,
                status = "failed",
                walletUnitId = unit.id,
                error = failure.message ?: failure.toString(),
            )
        } finally {
            // The pending case keeps the client alive for the resumed leg.
            if (pending.values.none { it.flowId == flowId }) client.close()
        }
    }

    /** Resumes a flow that was parked waiting for the browser redirect. */
    suspend fun completeAuthorization(code: String, state: String): IssuanceResult {
        val parked = pending.remove(state)
            ?: return IssuanceResult(
                flowId = "unknown",
                status = "failed",
                error = "No issuance flow is waiting for state '$state'",
            )
        return try {
            val credentials = redeem(
                flowId = parked.flowId,
                unit = parked.unit,
                issuer = parked.issuer,
                prepared = parked.prepared,
                configurationId = parked.configurationId,
                code = code,
                serverState = state,
                client = parked.client,
                copies = parked.copies,
            )
            IssuanceResult(
                flowId = parked.flowId,
                status = "issued",
                walletUnitId = parked.unit.id,
                credentials = credentials,
            )
        } catch (failure: Exception) {
            sink.error(parked.flowId, failure.message ?: failure.toString())
            IssuanceResult(
                flowId = parked.flowId,
                status = "failed",
                walletUnitId = parked.unit.id,
                error = failure.message ?: failure.toString(),
            )
        } finally {
            parked.client.close()
        }
    }

    /**
     * Resolve either a credential offer handed to us, or go straight to the issuer's
     * metadata and construct a wallet-initiated offer.
     */
    private suspend fun negotiate(
        flowId: String,
        request: IssuanceRequest,
        client: HttpClient,
        config: OpenId4VCIConfig,
        issuerRef: IssuerRef,
    ): IssuerNegotiationResult = when {
        request.offerUri != null -> {
            sink.step(flowId, "Resolving credential offer", actor = "issuer")
            Issuer.make(config, request.offerUri, client).getOrThrow()
        }
        request.credentialConfigurationId != null -> {
            sink.step(flowId, "Wallet-initiated issuance; fetching issuer metadata", actor = "issuer")
            Issuer.makeWalletInitiated(
                config,
                CredentialIssuerId(issuerRef.base).getOrThrow(),
                listOf(CredentialConfigurationIdentifier(request.credentialConfigurationId)),
                client,
            ).getOrThrow()
        }
        else -> error("Provide either offerUri or credentialConfigurationId")
    }

    private fun chooseConfiguration(
        issuer: Issuer,
        request: IssuanceRequest,
    ): CredentialConfigurationIdentifier {
        val offered = issuer.credentialOffer.credentialConfigurationIdentifiers
        request.credentialConfigurationId?.let { requested ->
            val match = offered.firstOrNull { it.value == requested }
            if (match != null) return match
        }
        return offered.firstOrNull() ?: error("The credential offer contains no credential configurations")
    }

    /** Exchange the authorisation code for a token, then ask for the credential. */
    private suspend fun redeem(
        flowId: String,
        unit: WalletUnit,
        issuer: Issuer,
        prepared: AuthorizationRequestPrepared,
        configurationId: CredentialConfigurationIdentifier,
        code: String,
        serverState: String,
        client: HttpClient,
        copies: Int,
    ): List<StoredCredential> = with(issuer) {
        sink.step(flowId, "Exchanging authorisation code for an access token", actor = "authorization-server")
        val authorized = with(prepared) {
            authorizeWithAuthorizationCode(AuthorizationCode(code), serverState).getOrThrow()
        }

        // One device key per requested copy. A single copy reuses the unit's device key
        // (keeping single issuance unchanged); a batch generates distinct keys, the first of
        // which also signs the proof. The issuer mints one credential per attested key.
        val batchSize = copies.coerceAtLeast(1)
        val deviceKeys =
            if (batchSize == 1) listOf(unit.keys.deviceKey)
            else unit.keys.newDeviceKeyBatch(batchSize)

        if (batchSize > 1) {
            sink.step(
                flowId,
                "Requesting $batchSize credential copies, each bound to a distinct device key (batch issuance)",
                actor = "issuer",
            )
        } else {
            sink.step(flowId, "Requesting credential with a JWT key-binding proof", actor = "issuer")
        }
        // The attestation embeds a fresh status list entry, and the issuer dereferences it,
        // so it is taken here rather than reused across flows.
        val proof = ProofSpecification.JwtProof { nonce, _ ->
            val status = keyStorageStatus.take(client, flowId)
            unit.keys.proofSigner(nonce?.value, status, flowId, deviceKeys)
        }

        val (_, outcome) = with(authorized) {
            request(IssuanceRequestPayload.ConfigurationBased(configurationId), proof).getOrThrow()
        }

        when (outcome) {
            is SubmissionOutcome.Success -> {
                val format = formatOf(issuer, configurationId)
                // Each returned credential is bound (cnf) to one of the attested keys. Match
                // credential to key by thumbprint rather than list order, so the key stored
                // with a copy is provably the one it was bound to even if order is not kept.
                val keysByThumbprint = deviceKeys.associateBy { it.toPublicJWK().computeThumbprint().toString() }
                outcome.credentials.map { issued ->
                    val raw = issued.credential.toString()
                    // The credential response is a JWE, so the scanner never saw this;
                    // hand it the decrypted credential so the trace is complete.
                    scanner.recordIssuedCredential(
                        flowId = flowId,
                        walletUnitId = unit.id,
                        raw = raw,
                        where = "decrypted from the issuer's credential response",
                    )
                    val boundKey = cnfThumbprint(raw)?.let { keysByThumbprint[it] } ?: deviceKeys.first()
                    unit.store.add(
                        configurationId = configurationId.value,
                        format = format,
                        raw = raw,
                        issuer = issuer.credentialOffer.credentialIssuerIdentifier.value.toString(),
                        deviceKey = boundKey,
                    )
                }.also { sink.step(flowId, "Stored ${it.size} credential(s) in wallet unit '${unit.label}'") }
            }

            is SubmissionOutcome.Deferred -> {
                sink.step(flowId, "Issuer deferred the credential (transaction ${outcome.transactionId.value})", actor = "issuer")
                error("Issuance was deferred; the testbed does not poll the deferred endpoint yet")
            }

            is SubmissionOutcome.Failed -> error("Issuer rejected the request: ${outcome.error}")
        }
    }

    /**
     * The JWK thumbprint of the `cnf` key an issued SD-JWT VC is bound to.
     *
     * Read from the issuer-signed JWT (the segment before the first `~`), so a batch copy
     * can be matched back to the device key it was bound to. Returns null for formats without
     * a parseable `cnf.jwk` (e.g. mso_mdoc), in which case the caller falls back to order.
     */
    private fun cnfThumbprint(raw: String): String? = runCatching {
        val issuerJwt = raw.substringBefore('~')
        val cnf = SignedJWT.parse(issuerJwt).jwtClaimsSet.getJSONObjectClaim("cnf") ?: return null
        @Suppress("UNCHECKED_CAST")
        val jwk = cnf["jwk"] as? Map<String, Any> ?: return null
        JWK.parse(jwk).computeThumbprint().toString()
    }.getOrNull()

    /** The format the issuer advertises for this configuration, used by the inspector. */
    private fun formatOf(issuer: Issuer, configurationId: CredentialConfigurationIdentifier): String {
        val configuration = issuer.credentialOffer.credentialIssuerMetadata
            .credentialConfigurationsSupported[configurationId]
        return when (configuration) {
            is MsoMdocCredential -> "mso_mdoc"
            is SdJwtVcCredential -> "dc+sd-jwt"
            else -> "unknown"
        }
    }

    /** Credential configurations the issuer supports, for the console's picker. */
    suspend fun catalogue(issuerId: String? = null): List<String> {
        val flowId = "meta-${UUID.randomUUID().toString().take(8)}"
        val issuerRef = registry.issuer(issuerId)
        val client = tracedHttpClient(flowId, sink)
        return try {
            val (metadata, _) = Issuer.metaData(
                client,
                CredentialIssuerId(issuerRef.base).getOrThrow(),
                IssuerMetadataPolicy.IgnoreSigned,
            )
            metadata.credentialConfigurationsSupported.keys.map { it.value }.sorted()
        } finally {
            client.close()
        }
    }
}
