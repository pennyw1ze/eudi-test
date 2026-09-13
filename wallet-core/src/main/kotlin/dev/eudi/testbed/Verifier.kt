package dev.eudi.testbed

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class InitTransactionResponse(
    @SerialName("transaction_id") val transactionId: String,
    @SerialName("client_id") val clientId: String,
    @SerialName("request_uri") val requestUri: String,
    @SerialName("request_uri_method") val requestUriMethod: String? = null,
)

/**
 * The verifier side of a presentation, driven through the reference verifier's own
 * Verifier API. The testbed plays the relying party here: it opens a transaction and
 * later reads back whatever the wallet posted.
 */
class VerifierDriver(private val sink: TraceSink) {

    suspend fun initTransaction(
        client: HttpClient,
        flowId: String,
        dcqlQuery: JsonObject,
        nonce: String,
        verifier: VerifierRef,
    ): InitTransactionResponse {
        sink.step(flowId, "Relying party '${verifier.label}' opens a presentation transaction", actor = "verifier")

        val response = client.post("${verifier.base}/ui/presentations") {
            contentType(ContentType.Application.Json)
            accept(ContentType.Application.Json)
            setBody(
                buildJsonObject {
                    put("dcql_query", dcqlQuery)
                    put("nonce", nonce)
                    put("jar_mode", "by_reference")
                    put("request_uri_method", "get")
                    put("response_mode", "direct_post")
                    put("profile", "openid4vp")
                    // Names one of the verifier's configured Wallet Relying Party Intended
                    // Uses, whose registration certificate is attached to the request. The
                    // reference verifier refuses a transaction without one
                    // ("MissingRegistrationCertificate").
                    put("intended_use_id", verifier.intendedUseId)
                },
            )
        }
        if (!response.status.isSuccess()) {
            error("Verifier refused to open a transaction (HTTP ${response.status.value}): ${response.bodyAsText()}")
        }
        return response.body()
    }

    /** The intended uses the verifier has configured, each with its registration certificate. */
    suspend fun intendedUses(client: HttpClient, verifier: VerifierRef): String =
        client.get("${verifier.base}/ui/intended-uses") {
            accept(ContentType.Application.Json)
        }.bodyAsText()

    /** What the verifier made of the wallet's response. */
    suspend fun walletResponse(
        client: HttpClient,
        flowId: String,
        transactionId: String,
        verifier: VerifierRef,
    ): JsonElement {
        sink.step(flowId, "Relying party reads the wallet response", actor = "verifier")
        val response = client.get("${verifier.base}/ui/presentations/$transactionId") {
            accept(ContentType.Application.Json)
        }
        val text = response.bodyAsText()
        return runCatching { lenientJson.parseToJsonElement(text) }
            .getOrElse { JsonPrimitive(text) }
    }

    /**
     * The URI a wallet would receive from a QR code or a deep link.
     */
    fun authorizationRequestUri(transaction: InitTransactionResponse, scheme: String = "eudi-openid4vp"): String =
        URLBuilder("$scheme://").apply {
            parameters.append("client_id", transaction.clientId)
            parameters.append("request_uri", transaction.requestUri)
            transaction.requestUriMethod?.let { parameters.append("request_uri_method", it) }
        }.buildString()

    companion object {
        /** A DCQL query asking for a few PID claims, used when the caller supplies none. */
        fun defaultDcqlQuery(): JsonObject = buildJsonObject {
            putJsonArray("credentials") {
                addJsonObject {
                    put("id", "pid")
                    put("format", "dc+sd-jwt")
                    putJsonObject("meta") {
                        putJsonArray("vct_values") { add("urn:eudi:pid:1") }
                    }
                    putJsonArray("claims") {
                        addJsonObject { putJsonArray("path") { add("family_name") } }
                        addJsonObject { putJsonArray("path") { add("given_name") } }
                    }
                }
            }
        }
    }
}
