package dev.eudi.testbed

import io.ktor.client.request.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Serializable

@Serializable
data class ComponentStatus(
    val id: String,
    val label: String,
    /** "up" when it answered, "down" when unreachable. */
    val state: String,
    val detail: String,
    val url: String,
)

/**
 * Reachability of every participant, so the console can show what is actually running
 * instead of failing later with a connection error.
 *
 * Any HTTP response counts as up: several of these endpoints answer 400 or 404 to a bare
 * probe, which still proves the service is listening behind the gateway.
 */
class StatusService {

    private data class Probe(
        val id: String,
        val label: String,
        val url: String,
        val method: HttpMethod = HttpMethod.Get,
    )

    private val probes = listOf(
        Probe("gateway", "Gateway", "${Env.publicOrigin}/"),
        Probe("issuer", "Issuer", "${Env.issuerBase}/.well-known/openid-credential-issuer"),
        Probe(
            "authorization-server",
            "Authorisation server",
            "${Env.publicOrigin}/idp/realms/pid-issuer-realm/.well-known/openid-configuration",
        ),
        Probe("status-list", "Status list", "${Env.publicOrigin}/token_status_list/"),
        Probe("verifier", "Verifier", "${Env.verifierBase}/ui/presentations", HttpMethod.Post),
    )

    suspend fun snapshot(): List<ComponentStatus> = coroutineScope {
        val client = plainHttpClient()
        try {
            probes.map { probe ->
                async {
                    val outcome = runCatching {
                        client.request(probe.url) {
                            method = probe.method
                            accept(ContentType.Application.Json)
                            if (probe.method == HttpMethod.Post) {
                                // An empty request is rejected, which is all the probe needs:
                                // a 4xx still proves the service is listening.
                                contentType(ContentType.Application.Json)
                                setBody("{}")
                            }
                        }
                    }
                    outcome.fold(
                        onSuccess = {
                            // Only a 5xx or a refused connection means something is wrong; these
                            // endpoints answer 4xx to a bare probe by design.
                            val healthy = it.status.value < 500
                            ComponentStatus(
                                probe.id,
                                probe.label,
                                if (healthy) "up" else "down",
                                if (it.status.value < 400) "HTTP ${it.status.value}" else "reachable (${it.status.value})",
                                probe.url,
                            )
                        },
                        onFailure = {
                            ComponentStatus(probe.id, probe.label, "down", it.message ?: "unreachable", probe.url)
                        },
                    )
                }
            }.map { it.await() }
        } finally {
            client.close()
        }
    }

    /** The issuer's metadata, shown verbatim on the issuer panel. */
    suspend fun issuerMetadata(): String {
        val client = plainHttpClient()
        return try {
            client.get("${Env.issuerBase}/.well-known/openid-credential-issuer") {
                accept(ContentType.Application.Json)
            }.bodyAsText()
        } finally {
            client.close()
        }
    }
}
