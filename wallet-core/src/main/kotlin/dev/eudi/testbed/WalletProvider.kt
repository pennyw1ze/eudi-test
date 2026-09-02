package dev.eudi.testbed

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.openid4vci.ClientAttestationJWT
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.JwsAlgorithm
import eu.europa.ec.eudi.openid4vci.PositiveDuration
import eu.europa.ec.eudi.openid4vci.ProvisionClientAttestation
import eu.europa.ec.eudi.openid4vci.Signer
import io.ktor.client.*
import java.time.Instant
import java.util.Date

/**
 * Stands in for the wallet provider, issuing the client attestation that the reference
 * issuer's authorisation server requires.
 *
 * The pid-issuer only accepts attestation-based client authentication: its credential
 * endpoint reads a `client_status` claim off the access token, and that claim only
 * reaches the token when Keycloak's ABCA extension has validated a client attestation.
 * Without one the endpoint fails with "Unexpected client_status claim type 'null'".
 *
 * In a real deployment the wallet receives this attestation from its provider. Here the
 * testbed signs its own, which the sample realm accepts because its `eudiw-abca` client
 * is configured with an empty `trustValidator.serviceUrl`.
 */
class WalletProviderAttestation(
    private val keys: WalletKeys,
    private val statusProvider: KeyStorageStatusProvider,
    private val client: HttpClient,
    private val flowId: String,
    private val sink: TraceSink,
    private val clientId: String,
) : ProvisionClientAttestation {

    override val algorithm: JwsAlgorithm = JwsAlgorithm("ES256")
    override val popAlgorithm: JwsAlgorithm = JwsAlgorithm("ES256")

    override suspend fun invoke(
        authorizationServer: HttpsUrl,
        preferredClientStatusPeriod: PositiveDuration?,
    ): ProvisionClientAttestation.Provisioned {
        sink.step(flowId, "Wallet provider issues a client attestation", actor = "authorization-server")

        // client_status is a status list reference, like the key attestation's; the
        // status list service allows this doctype for exactly this purpose.
        val status = statusProvider.take(client, flowId, doctype = "oauth-client-attestation+jwt")

        val now = Instant.now()
        val expiry = now.plusSeconds(3600)

        val claims = JWTClaimsSet.Builder()
            .issuer("https://localhost/eudi-testbed/wallet-provider")
            // The subject must be the client id the authorisation server knows.
            .subject(clientId)
            .issueTime(Date.from(now))
            .notBeforeTime(Date.from(now.minusSeconds(60)))
            .expirationTime(Date.from(expiry))
            .claim("cnf", mapOf("jwk" to keys.clientPopKey.toPublicJWK().toJSONObject()))
            .claim("wallet_name", "EUDI Testbed Wallet")
            .claim("wallet_version", "0.1.0")
            .claim(
                "wallet_solution_certification_information",
                mapOf(
                    "certification_id" to "eudi-testbed",
                    "certified_by" to "eudi-testbed",
                ),
            )
            .claim(
                "client_status",
                mapOf(
                    "status" to mapOf(
                        "status_list" to mapOf("idx" to status.index, "uri" to status.uri),
                    ),
                    "exp" to expiry.epochSecond,
                ),
            )
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("oauth-client-attestation+jwt"))
            .x509CertChain(listOf(keys.attestationCertificate.asX5cEntry()))
            .build()

        val attestation = keys.signAsWalletProvider(header, claims)

        return ProvisionClientAttestation.Provisioned(
            clientAttestation = ClientAttestationJWT(attestation.serialize()),
            popSigner = popSigner(),
        )
    }

    /** Proves possession of the key the attestation's `cnf` claim names. */
    private fun popSigner(): Signer<JWK> = EcSigner(keys.clientPopKey, keys.clientPopKey.toPublicJWK())
}
