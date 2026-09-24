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

private val session = SessionLog()
private val sink = TraceSink(session)
private val crypto = CryptoSink(session)
private val scanner = CryptoScanner(crypto)
private val registry = Registry(crypto)
private val verifierDriver = VerifierDriver(sink)
private val linkingIssuer = LinkingIssuer(crypto)
private val linkingVerifier = LinkingVerifier(listOf(linkingIssuer.trustedJwk()), crypto)
private val issuanceService = IssuanceService(sink, scanner, registry)
private val presentationService =
    PresentationService(sink, crypto, scanner, registry, verifierDriver, linkingIssuer, linkingVerifier)
private val statusService = StatusService(registry)

fun main() {
    val info = session.info()
    println()
    println("  EUDI testbed listening on  ->  http://localhost:${Env.port}")
    println("      issuer   ${Env.issuerBase}")
    println("      verifier ${Env.verifierBase}")
    println("      session  ${info.directory}")
    println()
    println("  This process stays running. Ctrl+C to stop it.")
    println()

    // Final counts belong in session.json; the traces themselves are already on disk.
    Runtime.getRuntime().addShutdownHook(Thread { session.seal() })

    try {
        embeddedServer(Netty, port = Env.port, host = "0.0.0.0", module = Application::testbed).start(wait = true)
    } catch (alreadyBound: java.net.BindException) {
        System.err.println("Port ${Env.port} is already in use — another testbed is probably running.")
        System.err.println("Stop it, or start this one on a different port with TESTBED_PORT=4001 make testbed")
        kotlin.system.exitProcess(1)
    }
}

/** Reads a string field from a posted JSON body, rejecting a blank one. */
private fun JsonObject.required(field: String): String =
    this[field]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }
        ?: error("'$field' is required")

private fun JsonObject.optional(field: String): String? =
    this[field]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }

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
                        put("walletRedirectUri", Env.redirectUri)
                        put("autoLoginUser", Env.autoLoginUser)
                    },
                )
            }

            /**
             * The sample natural persons issuance can authenticate as. The console
             * offers these so different wallet units can be issued different PIDs.
             */
            get("/subjects") {
                call.respond(Env.sampleSubjects)
            }

            /** Where this run is being recorded, and how much of it so far. */
            get("/session") {
                call.respond(session.info())
            }

            /** The crypto trace as it stands on disk, for download or offline replay. */
            get("/session/crypto-trace") {
                call.response.header(
                    HttpHeaders.ContentDisposition,
                    "attachment; filename=\"crypto-trace-${session.id}.jsonl\"",
                )
                call.respondText(session.cryptoTraceText(), ContentType.Text.Plain)
            }

            // ------------------------------------------------------ participants

            get("/wallet-units") {
                call.respond(registry.walletUnits().map { registry.info(it) })
            }

            post("/wallet-units") {
                val body = runCatching { call.receive<JsonObject>() }.getOrElse { buildJsonObject { } }
                val label = body.optional("label") ?: "Wallet unit ${registry.walletUnits().size + 1}"
                call.respond(registry.info(registry.addWalletUnit(label)))
            }

            post("/wallet-units/{id}/rename") {
                val body = call.receive<JsonObject>()
                val renamed = registry.renameWalletUnit(call.parameters["id"] ?: "", body.required("label"))
                call.respond(buildJsonObject { put("renamed", renamed) })
            }

            delete("/wallet-units/{id}") {
                call.respond(buildJsonObject { put("removed", registry.removeWalletUnit(call.parameters["id"] ?: "")) })
            }

            get("/issuers") { call.respond(registry.issuers().map { it.view() }) }

            post("/issuers") {
                val body = call.receive<JsonObject>()
                call.respond(
                    registry.addIssuer(
                        label = body.required("label"),
                        base = body.required("base"),
                        clientId = body.optional("clientId") ?: Env.walletClientId,
                        loginUser = body.optional("loginUser") ?: Env.autoLoginUser,
                        loginPassword = body.optional("loginPassword") ?: Env.autoLoginPassword,
                    ).view(),
                )
            }

            delete("/issuers/{id}") {
                call.respond(buildJsonObject { put("removed", registry.removeIssuer(call.parameters["id"] ?: "")) })
            }

            get("/verifiers") { call.respond(registry.verifiers()) }

            post("/verifiers") {
                val body = call.receive<JsonObject>()
                call.respond(
                    registry.addVerifier(
                        label = body.required("label"),
                        base = body.required("base"),
                        intendedUseId = body.optional("intendedUseId") ?: Env.verifierIntendedUseId,
                    ),
                )
            }

            delete("/verifiers/{id}") {
                call.respond(buildJsonObject { put("removed", registry.removeVerifier(call.parameters["id"] ?: "")) })
            }

            // ----------------------------------------------------------- issuer

            /** Credential configurations the issuer advertises. */
            get("/catalogue") {
                val configurations = runCatching {
                    issuanceService.catalogue(call.request.queryParameters["issuerId"])
                }
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

            /** Reachability of every participant, for the console's status strip. */
            get("/status") {
                call.respond(statusService.snapshot())
            }

            get("/issuer/metadata") {
                val metadata = runCatching { statusService.issuerMetadata(call.request.queryParameters["issuerId"]) }
                metadata.fold(
                    onSuccess = { call.respondText(it, ContentType.Application.Json) },
                    onFailure = {
                        call.respond(
                            HttpStatusCode.BadGateway,
                            buildJsonObject { put("error", it.message ?: it.toString()) },
                        )
                    },
                )
            }

            // ------------------------------------------------------------ verifier

            /**
             * Opens a presentation transaction without waiting for the wallet, so the
             * verifier panel can show the request and hand it to a phone by QR code.
             */
            post("/verifier/transaction") {
                val body = runCatching { call.receive<JsonObject>() }.getOrElse { buildJsonObject { } }
                val query = body["dcqlQuery"] as? JsonObject ?: VerifierDriver.defaultDcqlQuery()
                val verifierRef = registry.verifier(body.optional("verifierId"))
                val flowId = "vrf-" + java.util.UUID.randomUUID().toString().take(8)
                val client = tracedHttpClient(flowId, sink, scanner = scanner)
                try {
                    val nonce = java.util.UUID.randomUUID().toString()
                    val transaction = verifierDriver.initTransaction(client, flowId, query, nonce, verifierRef)
                    call.respond(
                        buildJsonObject {
                            put("flowId", flowId)
                            put("transactionId", transaction.transactionId)
                            put("clientId", transaction.clientId)
                            put("requestUri", transaction.requestUri)
                            put("authorizationRequestUri", verifierDriver.authorizationRequestUri(transaction))
                        },
                    )
                } catch (failure: Exception) {
                    sink.error(flowId, failure.message ?: failure.toString())
                    call.respond(
                        HttpStatusCode.BadGateway,
                        buildJsonObject { put("error", failure.message ?: failure.toString()) },
                    )
                } finally {
                    client.close()
                }
            }

            /** The intended uses the verifier offers, for the verifier panel's picker. */
            get("/verifier/intended-uses") {
                val verifierRef = registry.verifier(call.request.queryParameters["verifierId"])
                val client = plainHttpClient()
                try {
                    call.respondText(
                        verifierDriver.intendedUses(client, verifierRef),
                        ContentType.Application.Json,
                    )
                } catch (failure: Exception) {
                    call.respond(
                        HttpStatusCode.BadGateway,
                        buildJsonObject { put("error", failure.message ?: failure.toString()) },
                    )
                } finally {
                    client.close()
                }
            }

            /** Whatever the verifier has received for a transaction so far. */
            get("/verifier/transaction/{id}") {
                val id = call.parameters["id"] ?: ""
                val verifierRef = registry.verifier(call.request.queryParameters["verifierId"])
                val flowId = "vrf-read"
                val client = tracedHttpClient(flowId, sink, scanner = scanner)
                try {
                    call.respond(verifierDriver.walletResponse(client, flowId, id, verifierRef))
                } finally {
                    client.close()
                }
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
                val unit = registry.walletUnit(call.request.queryParameters["walletUnitId"])
                call.respond(unit.store.all())
            }

            get("/credentials/{id}") {
                val unit = registry.walletUnit(call.request.queryParameters["walletUnitId"])
                val credential = unit.store.get(call.parameters["id"] ?: "")
                if (credential == null) {
                    call.respond(HttpStatusCode.NotFound, buildJsonObject { put("error", "no such credential") })
                } else {
                    call.respond(Inspector.inspect(credential))
                }
            }

            delete("/credentials/{id}") {
                val unit = registry.walletUnit(call.request.queryParameters["walletUnitId"])
                call.respond(buildJsonObject { put("removed", unit.store.remove(call.parameters["id"] ?: "")) })
            }

            post("/credentials/clear") {
                val body = runCatching { call.receive<JsonObject>() }.getOrElse { buildJsonObject { } }
                registry.walletUnit(body.optional("walletUnitId")).store.clear()
                call.respond(buildJsonObject { put("cleared", true) })
            }

            // ------------------------------------------------------ presentation

            post("/present") {
                val request = runCatching { call.receive<PresentationRequest>() }.getOrElse { PresentationRequest() }
                call.respond(presentationService.present(request))
            }

            /**
             * The pooling attack (Attack A): two or more colluding wallet units jointly
             * satisfy one verifier request, each signing its own key binding JWT.
             */
            post("/present/pooled") {
                val request = runCatching { call.receive<PooledPresentationRequest>() }.getOrElse { PooledPresentationRequest() }
                call.respond(presentationService.presentPooled(request))
            }

            /**
             * The linking-issuer countermeasure: the same request as a pooled presentation,
             * but each contributing unit proves co-residency of the key it signs with, the
             * linking issuer binds the keys, and the verifier runs the extra link check. One
             * unit is accepted; a pool of two or more is now rejected.
             */
            post("/present/linked") {
                val request = runCatching { call.receive<LinkedPresentationRequest>() }.getOrElse { LinkedPresentationRequest() }
                call.respond(presentationService.presentLinked(request))
            }

            // ------------------------------------------------------------ traces

            /** The cryptographic timeline: who proved what, over which key. */
            get("/crypto") {
                val since = call.request.queryParameters["since"]?.toLongOrNull() ?: 0L
                val flowId = call.request.queryParameters["flowId"]
                call.respond(crypto.since(since, flowId))
            }

            /** Every key seen so far, so the console can colour the binding chain. */
            get("/crypto/keys") {
                call.respond(crypto.keys())
            }

            /** The network timeline, kept as the underlying evidence for the above. */
            get("/trace") {
                val since = call.request.queryParameters["since"]?.toLongOrNull() ?: 0L
                val flowId = call.request.queryParameters["flowId"]
                call.respond(sink.since(since, flowId))
            }
        }
    }
}
