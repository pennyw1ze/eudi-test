package dev.eudi.testbed

import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

@Serializable
data class IssuanceRequest(
    /** A credential offer URI, if you already have one. */
    val offerUri: String? = null,
    /** Otherwise, ask the issuer directly for this configuration (wallet-initiated). */
    val credentialConfigurationId: String? = null,
    /** Log in headlessly with the sample realm user instead of using a browser. */
    val autoLogin: Boolean = true,
    val username: String? = null,
    val password: String? = null,
)

@Serializable
data class IssuanceResult(
    val flowId: String,
    val status: String,
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
    private val store: CredentialStore,
    private val keys: WalletKeys,
) {

    private val keyStorageStatus = KeyStorageStatusProvider(sink)

    /** Flows paused waiting for a browser redirect, keyed by OAuth state. */
    private data class Pending(
        val flowId: String,
        val issuer: Issuer,
        val prepared: AuthorizationRequestPrepared,
        val configurationId: CredentialConfigurationIdentifier,
        val client: HttpClient,
    )

    private val pending = ConcurrentHashMap<String, Pending>()

    private val config = OpenId4VCIConfig(
        clientId = Env.walletClientId,
        authFlowRedirectionURI = URI.create(Env.redirectUri),
        encryptionSupportConfig = EncryptionSupportConfig(
            ecKeyCurve = com.nimbusds.jose.jwk.Curve.P_256,
            rcaKeySize = 2048,
            credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
        ),
        // The upstream realm runs Keycloak with the dpop feature on and the issuer sets
        // ISSUER_DPOP_REALM, so its token endpoint rejects requests without a DPoP proof.
        // IfSupported means the wallet still works against an issuer that does not want one.
        dPoPUsage = DPoPUsage.IfSupported(
            DPoPConfig(
                object : ProvisionDPoPSigner {
                    override val popAlgorithm: JwsAlgorithm = JwsAlgorithm("ES256")
                    override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> =
                        EcSigner(keys.dpopKey, keys.dpopKey.toPublicJWK())
                },
            ),
        ),
    )

    suspend fun issue(request: IssuanceRequest): IssuanceResult {
        val flowId = "iss-${UUID.randomUUID().toString().take(8)}"
        val client = tracedHttpClient(flowId, sink, withCookies = true)

        return try {
            sink.step(flowId, "Starting OpenID4VCI issuance")

            val (issuer, warnings) = negotiate(flowId, request, client)
            val configurationId = chooseConfiguration(issuer, request)

            sink.step(
                flowId,
                "Issuer ${issuer.credentialOffer.credentialIssuerIdentifier.value} offers '${configurationId.value}'",
                actor = "issuer",
            )

            val prepared = with(issuer) { prepareAuthorizationRequest().getOrThrow() }
            val authorizationUrl = prepared.authorizationCodeURL.value.toString()

            if (!request.autoLogin) {
                pending[prepared.state] = Pending(flowId, issuer, prepared, configurationId, client)
                sink.step(flowId, "Waiting for the user to log in via the browser")
                return IssuanceResult(
                    flowId = flowId,
                    status = "awaiting-authorization",
                    authorizationUrl = authorizationUrl,
                    warnings = warnings.map { it.toString() },
                )
            }

            val callback = KeycloakLogin.authorize(
                client = client,
                authorizationUrl = authorizationUrl,
                username = request.username ?: Env.autoLoginUser,
                password = request.password ?: Env.autoLoginPassword,
                sink = sink,
                flowId = flowId,
            )

            val credentials = redeem(
                flowId = flowId,
                issuer = issuer,
                prepared = prepared,
                configurationId = configurationId,
                code = callback.code,
                serverState = callback.state ?: prepared.state,
                client = client,
            )

            IssuanceResult(
                flowId = flowId,
                status = "issued",
                credentials = credentials,
                warnings = warnings.map { it.toString() },
            )
        } catch (failure: Exception) {
            sink.error(flowId, failure.message ?: failure.toString())
            IssuanceResult(flowId = flowId, status = "failed", error = failure.message ?: failure.toString())
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
                issuer = parked.issuer,
                prepared = parked.prepared,
                configurationId = parked.configurationId,
                code = code,
                serverState = state,
                client = parked.client,
            )
            IssuanceResult(flowId = parked.flowId, status = "issued", credentials = credentials)
        } catch (failure: Exception) {
            sink.error(parked.flowId, failure.message ?: failure.toString())
            IssuanceResult(flowId = parked.flowId, status = "failed", error = failure.message ?: failure.toString())
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
    ): IssuerNegotiationResult = when {
        request.offerUri != null -> {
            sink.step(flowId, "Resolving credential offer", actor = "issuer")
            Issuer.make(config, request.offerUri, client).getOrThrow()
        }
        request.credentialConfigurationId != null -> {
            sink.step(flowId, "Wallet-initiated issuance; fetching issuer metadata", actor = "issuer")
            Issuer.makeWalletInitiated(
                config,
                CredentialIssuerId(Env.issuerBase).getOrThrow(),
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
        issuer: Issuer,
        prepared: AuthorizationRequestPrepared,
        configurationId: CredentialConfigurationIdentifier,
        code: String,
        serverState: String,
        client: HttpClient,
    ): List<StoredCredential> = with(issuer) {
        sink.step(flowId, "Exchanging authorisation code for an access token", actor = "authorization-server")
        val authorized = with(prepared) {
            authorizeWithAuthorizationCode(AuthorizationCode(code), serverState).getOrThrow()
        }

        sink.step(flowId, "Requesting credential with a JWT key-binding proof", actor = "issuer")
        // The attestation embeds a fresh status list entry, and the issuer dereferences it,
        // so it is taken here rather than reused across flows.
        val proof = ProofSpecification.JwtProof { nonce, _ ->
            val status = keyStorageStatus.take(client, flowId)
            keys.proofSigner(nonce?.value, status)
        }

        val (_, outcome) = with(authorized) {
            request(IssuanceRequestPayload.ConfigurationBased(configurationId), proof).getOrThrow()
        }

        when (outcome) {
            is SubmissionOutcome.Success -> {
                val format = formatOf(issuer, configurationId)
                outcome.credentials.map { issued ->
                    store.add(
                        configurationId = configurationId.value,
                        format = format,
                        raw = issued.credential.toString(),
                        issuer = issuer.credentialOffer.credentialIssuerIdentifier.value.toString(),
                    )
                }.also { sink.step(flowId, "Stored ${it.size} credential(s) in the wallet") }
            }

            is SubmissionOutcome.Deferred -> {
                sink.step(flowId, "Issuer deferred the credential (transaction ${outcome.transactionId.value})", actor = "issuer")
                error("Issuance was deferred; the testbed does not poll the deferred endpoint yet")
            }

            is SubmissionOutcome.Failed -> error("Issuer rejected the request: ${outcome.error}")
        }
    }

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
    suspend fun catalogue(): List<String> {
        val flowId = "meta-${UUID.randomUUID().toString().take(8)}"
        val client = tracedHttpClient(flowId, sink)
        return try {
            val (metadata, _) = Issuer.metaData(
                client,
                CredentialIssuerId(Env.issuerBase).getOrThrow(),
                IssuerMetadataPolicy.IgnoreSigned,
            )
            metadata.credentialConfigurationsSupported.keys.map { it.value }.sorted()
        } finally {
            client.close()
        }
    }
}
