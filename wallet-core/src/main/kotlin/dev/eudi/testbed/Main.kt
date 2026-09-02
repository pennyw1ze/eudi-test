package dev.eudi.testbed

import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.http.content.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.*

private val sink = TraceSink()
private val store = CredentialStore()
private val keys = WalletKeys()
private val verifierDriver = VerifierDriver(sink)
private val issuanceService = IssuanceService(sink, store, keys)
private val presentationService = PresentationService(sink, store, keys, verifierDriver)

fun main() {
    println()
    println("  EUDI testbed listening on  ->  http://localhost:${Env.port}")
    println("      issuer   ${Env.issuerBase}")
    println("      verifier ${Env.verifierBase}")
    println()
    println("  This process stays running. Ctrl+C to stop it.")
    println()
    embeddedServer(Netty, port = Env.port, host = "0.0.0.0", module = Application::testbed).start(wait = true)
}

fun Application.testbed() {
    install(ContentNegotiation) { json(lenientJson) }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            call.respond(
                HttpStatusCode.InternalServerError,
                buildJsonObject { put("error", cause.message ?: cause.toString()) },
            )
        }
    }

    routing {
        // ---------------------------------------------------------- console UI
        staticResources("/", "web") { default("index.html") }

        route("/api") {

            get("/health") {
                call.respond(buildJsonObject { put("status", "up") })
            }

            get("/config") {
                call.respond(
                    buildJsonObject {
                        put("publicOrigin", Env.publicOrigin)
                        put("issuerBase", Env.issuerBase)
                        put("verifierBase", Env.verifierBase)
                        put("walletRedirectUri", Env.redirectUri)
                        put("autoLoginUser", Env.autoLoginUser)
                    },
                )
            }

            /** Credential configurations the issuer advertises. */
            get("/catalogue") {
                val configurations = runCatching { issuanceService.catalogue() }
                call.respond(
                    buildJsonObject {
                        configurations.fold(
                            onSuccess = { ids ->
                                put("configurations", buildJsonArray { ids.forEach { add(it) } })
                            },
                            onFailure = { put("error", it.message ?: it.toString()) },
                        )
                    },
                )
            }

            // ---------------------------------------------------------- issuance

            post("/issue") {
                call.respond(issuanceService.issue(call.receive<IssuanceRequest>()))
            }

            /** Where the authorisation server redirects when a browser does the login. */
            get("/issuance/callback") {
                val code = call.request.queryParameters["code"]
                val state = call.request.queryParameters["state"]
                if (code == null || state == null) {
                    val error = call.request.queryParameters["error"] ?: "missing code or state"
                    call.respondText("Authorisation failed: $error", status = HttpStatusCode.BadRequest)
                    return@get
                }
                val result = issuanceService.completeAuthorization(code, state)
                // Land the browser back on the console rather than on raw JSON.
                call.respondRedirect("/?flow=${result.flowId}")
            }

            // ------------------------------------------------------- credentials

            get("/credentials") {
                call.respond(store.all())
            }

            get("/credentials/{id}") {
                val credential = store.get(call.parameters["id"] ?: "")
                if (credential == null) {
                    call.respond(HttpStatusCode.NotFound, buildJsonObject { put("error", "no such credential") })
                } else {
                    call.respond(Inspector.inspect(credential))
                }
            }

            delete("/credentials/{id}") {
                val removed = store.remove(call.parameters["id"] ?: "")
                call.respond(buildJsonObject { put("removed", removed) })
            }

            post("/credentials/clear") {
                store.clear()
                call.respond(buildJsonObject { put("cleared", true) })
            }

            // ------------------------------------------------------ presentation

            post("/present") {
                val request = runCatching { call.receive<PresentationRequest>() }.getOrElse { PresentationRequest() }
                call.respond(presentationService.present(request))
            }

            // ------------------------------------------------------------- trace

            get("/trace") {
                val since = call.request.queryParameters["since"]?.toLongOrNull() ?: 0L
                val flowId = call.request.queryParameters["flowId"]
                call.respond(sink.since(since, flowId))
            }
        }
    }
}
