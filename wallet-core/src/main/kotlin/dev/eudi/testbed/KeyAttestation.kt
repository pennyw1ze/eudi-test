package dev.eudi.testbed

import com.nimbusds.jose.util.Base64
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.json.*
import java.time.LocalDate
import java.time.format.DateTimeFormatter

/**
 * A status list entry, as handed out by the status list service.
 *
 * The reference issuer will not accept a key attestation without one: it dereferences
 * the URI and refuses the attestation unless the index reads back as VALID.
 */
data class KeyStorageStatusEntry(val index: Int, val uri: String)

/**
 * Takes a status list entry for a key attestation.
 *
 * A real wallet provider would own this step. The testbed does it against the same
 * status list service the issuer uses, which is why the entry validates.
 */
class KeyStorageStatusProvider(private val sink: TraceSink) {

    suspend fun take(
        client: HttpClient,
        flowId: String,
        doctype: String = "key-attestation+jwt",
    ): KeyStorageStatusEntry {
        sink.step(flowId, "Taking a status list entry for '$doctype'", actor = "issuer")

        val expiry = LocalDate.now().plusYears(1).format(DateTimeFormatter.ISO_LOCAL_DATE)
        val response = client.submitForm(
            url = "${Env.publicOrigin}/token_status_list/take",
            formParameters = parameters {
                append("doctype", doctype)
                append("country", Env.statusListCountry)
                append("expiry_date", expiry)
            },
        ) { header("X-Api-Key", Env.statusListApiKey) }

        val body = response.bodyAsText()
        if (!response.status.isSuccess()) {
            error("Status list service refused to issue an entry (HTTP ${response.status.value}): $body")
        }

        val statusList = lenientJson.parseToJsonElement(body).jsonObject["status_list"]?.jsonObject
            ?: error("Status list response carried no status_list object: $body")

        return KeyStorageStatusEntry(
            index = statusList["idx"]!!.jsonPrimitive.int,
            uri = statusList["uri"]!!.jsonPrimitive.content,
        )
    }
}

/** Encodes a certificate for the JWS `x5c` header, which the issuer requires. */
internal fun java.security.cert.X509Certificate.asX5cEntry(): Base64 = Base64.encode(encoded)
