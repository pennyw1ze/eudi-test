package dev.eudi.testbed

import kotlinx.serialization.json.*
import java.net.URLDecoder
import java.util.concurrent.ConcurrentHashMap

/**
 * Recovers the cryptographic layer of the protocol from the exchanges on the wire.
 *
 * Every proof in OpenID4VCI and OpenID4VP travels as a JOSE artefact in a header, a
 * form field or a JSON member. Reading them back off the wire — rather than emitting
 * events from inside the wallet — has one decisive advantage: it records what the
 * counterparty actually received, including everything the EUDI libraries construct
 * internally and the testbed never sees as an object.
 *
 * Artefacts repeat: one access token rides every subsequent request. Each distinct
 * serialization is therefore reported once, the first time it appears.
 */
class CryptoScanner(private val crypto: CryptoSink) {

    private val seen = ConcurrentHashMap.newKeySet<String>()

    /** Everything the interceptor observed about one request/response pair. */
    data class Exchange(
        val flowId: String,
        val walletUnitId: String?,
        val method: String,
        val url: String,
        val status: Int?,
        val requestHeaders: Map<String, String>,
        val requestBody: String?,
        val responseHeaders: Map<String, String>,
        val responseBody: String?,
    )

    fun scan(exchange: Exchange) = runCatching { scanUnsafe(exchange) }.getOrElse {
        // A malformed artefact must never break the flow it belongs to; the network log
        // still holds the bytes, so the loss is only in the interpretation.
        crypto.record(
            flowId = exchange.flowId,
            operation = "verify",
            actor = "wallet",
            artifact = "Trace decoding",
            summary = "Could not decode the cryptographic content of this exchange",
            onWire = "${exchange.method} ${exchange.url}",
            caveat = it.message,
            walletUnitId = exchange.walletUnitId,
        )
    }

    private fun scanUnsafe(exchange: Exchange) {
        val where = "${exchange.method} ${exchange.url}"
        val headers = exchange.requestHeaders.mapKeys { it.key.lowercase() }

        headers["dpop"]?.let { dpopProof(exchange, it, where) }
        headers["oauth-client-attestation"]?.let { clientAttestation(exchange, it, where) }
        headers["oauth-client-attestation-pop"]?.let {
            clientAttestationPop(exchange, it, where, headers["oauth-client-attestation"])
        }
        headers["authorization"]?.let { value ->
            value.substringAfter(' ', "").takeIf { it.isNotBlank() }?.let { accessToken(exchange, it, where, "presented") }
        }

        scanRequestBody(exchange, where)
        scanResponseBody(exchange, where)
    }

    /**
     * A JWE envelope: the exchange is confidential, so its contents cannot be read here.
     *
     * The reference issuer encrypts both the credential request and the credential
     * response. Recording the envelope keeps the trace honest — it says why the proof
     * and the credential appear from inside the wallet rather than off the wire, instead
     * of leaving a silent gap where the most important step should be.
     */
    private fun encryptedEnvelope(exchange: Exchange, body: String, direction: String, where: String) {
        val compact = body.trim()
        if (!seen.add(compact.take(200))) return
        val header = Jose.encryptedHeader(compact)
        crypto.record(
            flowId = exchange.flowId,
            operation = "bind",
            actor = if (direction == "request") "wallet" else "issuer",
            artifact = "Encrypted $direction (JWE)",
            summary = "The $direction is sealed to the recipient's public key, so nothing in it is " +
                "readable on the wire — its contents are recorded from inside the wallet instead",
            algorithm = listOfNotNull(
                header?.get("alg")?.jsonPrimitive?.contentOrNull,
                header?.get("enc")?.jsonPrimitive?.contentOrNull,
            ).joinToString(" + ").ifBlank { null },
            keys = listOfNotNull(
                header?.get("epk")?.let { Jose.keyRef(it, "ephemeral (ECDH-ES)") },
            ),
            binds = buildMap {
                header?.get("kid")?.jsonPrimitive?.contentOrNull?.let { put("recipient key id", it) }
                header?.get("cty")?.jsonPrimitive?.contentOrNull?.let { put("content type", it) }
            },
            header = header,
            onWire = where,
            walletUnitId = exchange.walletUnitId,
        )
    }

    /**
     * Records a credential the wallet decrypted, as if it had been observed.
     *
     * Called from the issuance flow because the credential response is a JWE; without
     * this the single most important artefact of OpenID4VCI would be missing from a
     * trace whose whole purpose is to show it.
     */
    fun recordIssuedCredential(flowId: String, walletUnitId: String?, raw: String, where: String) =
        issuedCredential(
            Exchange(flowId, walletUnitId, "POST", where, 200, emptyMap(), null, emptyMap(), null),
            raw,
            where,
        )

    // ------------------------------------------------------------ request side

    private fun scanRequestBody(exchange: Exchange, where: String) {
        val body = exchange.requestBody?.takeIf { it.isNotBlank() } ?: return
        val contentType = exchange.requestHeaders.entries
            .firstOrNull { it.key.equals("content-type", true) }?.value.orEmpty()

        if (Jose.looksEncrypted(body)) {
            encryptedEnvelope(exchange, body, "request", where)
            return
        }

        if (contentType.contains("json")) {
            val json = runCatching { lenientJson.parseToJsonElement(body) }.getOrNull() as? JsonObject ?: return
            // OpenID4VCI 1.0 credential request: one `proof` or a `proofs` bundle.
            (json["proof"] as? JsonObject)?.get("jwt")?.jsonPrimitive?.contentOrNull
                ?.let { credentialProof(exchange, it, where) }
            (json["proofs"] as? JsonObject)?.get("jwt")?.jsonArray?.forEach { element ->
                element.jsonPrimitive.contentOrNull?.let { credentialProof(exchange, it, where) }
            }
        } else {
            val form = parseForm(body)
            // direct_post carries the presentation itself.
            form["vp_token"]?.let { value -> eachPresentation(value) { vpToken(exchange, it, where) } }
            form["request"]?.let { requestObject(exchange, it, where) }
        }
    }

    // ----------------------------------------------------------- response side

    private fun scanResponseBody(exchange: Exchange, where: String) {
        val body = exchange.responseBody?.takeIf { it.isNotBlank() } ?: return
        val contentType = exchange.responseHeaders.entries
            .firstOrNull { it.key.equals("content-type", true) }?.value.orEmpty()

        if (Jose.looksEncrypted(body)) {
            encryptedEnvelope(exchange, body, "response", where)
            return
        }

        // A JAR request object and a status list token arrive as a bare JWS.
        if (Jose.looksCompact(body.trim())) {
            when {
                contentType.contains("authz-req") -> requestObject(exchange, body.trim(), where)
                contentType.contains("statuslist") -> statusListToken(exchange, body.trim(), where)
                else -> Unit
            }
            return
        }

        val json = runCatching { lenientJson.parseToJsonElement(body) }.getOrNull() as? JsonObject ?: return
        json["access_token"]?.jsonPrimitive?.contentOrNull?.let { accessToken(exchange, it, where, "issued") }
        json["credential"]?.jsonPrimitive?.contentOrNull?.let { issuedCredential(exchange, it, where) }
        (json["credentials"] as? JsonArray)?.forEach { element ->
            val raw = (element as? JsonObject)?.get("credential")?.jsonPrimitive?.contentOrNull
                ?: element.jsonPrimitive.contentOrNull
            raw?.let { issuedCredential(exchange, it, where) }
        }
        // The verifier's own API echoes the presentation it received.
        json["vp_token"]?.let { value -> eachPresentation(value) { vpToken(exchange, it, where) } }
    }

    // ------------------------------------------------------------- classifiers

    private fun dpopProof(exchange: Exchange, compact: String, where: String) {
        val jws = fresh(compact) ?: return
        val claims = jws.claims
        crypto.record(
            flowId = exchange.flowId,
            operation = "sign",
            actor = "wallet",
            artifact = "DPoP proof",
            summary = "Wallet proves possession of its DPoP key for this exact request, " +
                "so a stolen access token cannot be replayed from anywhere else",
            algorithm = jws.algorithm,
            keys = listOfNotNull(Jose.signerOf(jws, "dpop", storage = SOFTWARE)),
            binds = buildMap {
                claims?.get("htm")?.jsonPrimitive?.contentOrNull?.let { put("http method", it) }
                claims?.get("htu")?.jsonPrimitive?.contentOrNull?.let { put("http uri", it) }
                claims?.get("jti")?.jsonPrimitive?.contentOrNull?.let { put("jti (replay guard)", it) }
                claims?.get("ath")?.jsonPrimitive?.contentOrNull?.let { put("access token hash", it) }
                claims?.get("nonce")?.jsonPrimitive?.contentOrNull?.let { put("server nonce", it) }
            },
            header = jws.header,
            payload = jws.payload,
            onWire = where,
            compact = compact,
            walletUnitId = exchange.walletUnitId,
        )
    }

    private fun clientAttestation(exchange: Exchange, compact: String, where: String) {
        val jws = fresh(compact) ?: return
        val claims = jws.claims
        val bound = claims?.get("cnf")?.jsonObject?.get("jwk")
        crypto.record(
            flowId = exchange.flowId,
            operation = "sign",
            actor = "wallet-provider",
            artifact = "Client attestation (WIA)",
            summary = "The wallet provider vouches that this wallet instance is genuine, " +
                "and names the key it must prove possession of",
            algorithm = jws.algorithm,
            keys = listOfNotNull(
                Jose.signerOf(jws, "wallet-provider", storage = SOFTWARE),
                bound?.let { Jose.keyRef(it, "client-pop", storage = SOFTWARE) },
            ),
            binds = buildMap {
                claims?.get("iss")?.jsonPrimitive?.contentOrNull?.let { put("attested by", it) }
                claims?.get("sub")?.jsonPrimitive?.contentOrNull?.let { put("client id", it) }
                bound?.let { key -> Jose.thumbprint(key)?.let { put("cnf.jwk (key to prove)", it) } }
                claims?.get("client_status")?.let { put("status reference", statusRef(it)) }
                Jose.x5cSubject(jws)?.let { put("x5c subject", it) }
            },
            header = jws.header,
            payload = jws.payload,
            onWire = where,
            caveat = SELF_ATTESTED,
            compact = compact,
            walletUnitId = exchange.walletUnitId,
        )
    }

    private fun clientAttestationPop(exchange: Exchange, compact: String, where: String, attestation: String?) {
        val jws = fresh(compact) ?: return
        val claims = jws.claims
        // The PoP header carries no key: the whole point is that the verifier learns it
        // from the attestation's `cnf`. Both travel on this same request, so the trace
        // can make that link explicit rather than showing an unattributed signature.
        val confirmed = attestation
            ?.let { Jose.parse(it) }
            ?.claims?.get("cnf")?.jsonObject?.get("jwk")
            ?.let { Jose.keyRef(it, "client-pop", storage = SOFTWARE) }
        crypto.record(
            flowId = exchange.flowId,
            operation = "sign",
            actor = "wallet",
            artifact = "Client attestation PoP",
            summary = "Wallet proves it holds the key the attestation named, which is what " +
                "turns the provider's vouching into authentication of this instance",
            algorithm = jws.algorithm,
            keys = listOfNotNull(Jose.signerOf(jws, "client-pop", storage = SOFTWARE) ?: confirmed),
            binds = buildMap {
                claims?.get("aud")?.let { put("audience", it.toString().trim('"')) }
                claims?.get("jti")?.jsonPrimitive?.contentOrNull?.let { put("jti (replay guard)", it) }
                claims?.get("exp")?.jsonPrimitive?.contentOrNull?.let { put("expires", it) }
            },
            header = jws.header,
            payload = jws.payload,
            onWire = where,
            compact = compact,
            walletUnitId = exchange.walletUnitId,
        )
    }

    private fun accessToken(exchange: Exchange, compact: String, where: String, direction: String) {
        val jws = fresh(compact) ?: return
        val claims = jws.claims
        val confirmation = claims?.get("cnf")?.jsonObject
        crypto.record(
            flowId = exchange.flowId,
            operation = if (direction == "issued") "sign" else "bind",
            actor = if (direction == "issued") "authorization-server" else "wallet",
            artifact = "Access token",
            summary = if (direction == "issued") {
                "Authorisation server issues a token bound to the wallet's DPoP key, " +
                    "so it is useless to a bearer who does not hold that key"
            } else {
                "Wallet presents the access token alongside a matching DPoP proof"
            },
            algorithm = jws.algorithm,
            keys = emptyList(),
            binds = buildMap {
                confirmation?.get("jkt")?.jsonPrimitive?.contentOrNull?.let { put("cnf.jkt (DPoP key)", it) }
                claims?.get("client_status")?.let { put("client status", statusRef(it)) }
                claims?.get("aud")?.let { put("audience", it.toString().trim('"')) }
                claims?.get("scope")?.jsonPrimitive?.contentOrNull?.let { put("scope", it) }
            },
            header = jws.header,
            payload = jws.payload,
            onWire = where,
            compact = compact,
            walletUnitId = exchange.walletUnitId,
        )
    }

    /**
     * The JWT proof of a credential request, and the key attestation nested in its header.
     *
     * These two are the hinge of the whole issuance: the proof shows the wallet controls
     * the key, the attestation asserts where that key lives. Only the second one can
     * carry an assurance level, and only its signer's trustworthiness makes it mean
     * anything.
     */
    private fun credentialProof(exchange: Exchange, compact: String, where: String) {
        val jws = fresh(compact) ?: return
        val claims = jws.claims
        val signer = Jose.signerOf(jws, "device", storage = SOFTWARE)

        jws.header["key_attestation"]?.jsonPrimitive?.contentOrNull?.let {
            keyAttestation(exchange, it, where)
        }

        crypto.record(
            flowId = exchange.flowId,
            operation = "sign",
            actor = "wallet",
            artifact = "Credential request proof (JWT)",
            summary = "Wallet proves control of the key the credential will be bound to, " +
                "over a nonce the issuer chose so the proof cannot be pre-computed",
            algorithm = jws.algorithm,
            keys = listOfNotNull(signer),
            binds = buildMap {
                claims?.get("nonce")?.jsonPrimitive?.contentOrNull?.let { put("issuer nonce (c_nonce)", it) }
                claims?.get("aud")?.let { put("audience", it.toString().trim('"')) }
                claims?.get("iat")?.jsonPrimitive?.contentOrNull?.let { put("issued at", it) }
                if (jws.header.containsKey("key_attestation")) put("key attestation", "attached in header")
            },
            header = jws.header,
            payload = jws.payload,
            onWire = where,
            compact = compact,
            walletUnitId = exchange.walletUnitId,
        )
    }

    private fun keyAttestation(exchange: Exchange, compact: String, where: String) {
        val jws = fresh(compact) ?: return
        val claims = jws.claims
        val attested = claims?.get("attested_keys")?.jsonArray.orEmpty()
        val storage = claims?.get("key_storage")?.jsonArray?.mapNotNull { it.jsonPrimitive.contentOrNull }.orEmpty()
        val authentication = claims?.get("user_authentication")?.jsonArray
            ?.mapNotNull { it.jsonPrimitive.contentOrNull }.orEmpty()

        crypto.record(
            flowId = exchange.flowId,
            operation = "sign",
            actor = "wallet-provider",
            artifact = "Key attestation",
            summary = "The wallet provider asserts the assurance level of the device key: " +
                "where it is stored and how the user is authenticated before it is used",
            algorithm = jws.algorithm,
            keys = listOfNotNull(Jose.signerOf(jws, "wallet-provider", storage = SOFTWARE)) +
                attested.mapNotNull { Jose.keyRef(it, "device", storage = SOFTWARE) },
            binds = buildMap {
                put("attested keys", attested.size.toString())
                if (storage.isNotEmpty()) put("key_storage", storage.joinToString(", "))
                if (authentication.isNotEmpty()) put("user_authentication", authentication.joinToString(", "))
                claims?.get("certification")?.jsonPrimitive?.contentOrNull?.let { put("certification", it) }
                claims?.get("key_storage_status")?.let { put("status reference", statusRef(it)) }
                Jose.x5cSubject(jws)?.let { put("x5c subject", it) }
            },
            header = jws.header,
            payload = jws.payload,
            onWire = where,
            caveat = "Asserts ${storage.joinToString(", ").ifBlank { "an assurance level" }} while the private key " +
                "is held in this JVM's heap. The claim is signed by the testbed itself, and the issuer accepts it " +
                "only because its trust validator is switched off. No protocol check can detect this.",
            compact = compact,
            walletUnitId = exchange.walletUnitId,
        )
    }

    private fun issuedCredential(exchange: Exchange, raw: String, where: String) {
        val sdJwt = Jose.parseSdJwt(raw)
        if (sdJwt != null) {
            if (!seen.add(sdJwt.issuerJwt.serialized)) return
            val claims = sdJwt.issuerJwt.claims
            val bound = claims?.get("cnf")?.jsonObject?.get("jwk")
            val committed = Jose.committedDigests(sdJwt.issuerJwt.payload)
            crypto.record(
                flowId = exchange.flowId,
                operation = "sign",
                actor = "issuer",
                artifact = "Issued credential (SD-JWT VC)",
                summary = "Issuer signs the credential over the digests of its claims, and binds it " +
                    "to the wallet's device key — nobody else can ever present it",
                algorithm = sdJwt.issuerJwt.algorithm,
                keys = listOfNotNull(
                    Jose.signerOf(sdJwt.issuerJwt, "issuer"),
                    bound?.let { Jose.keyRef(it, "device", storage = SOFTWARE) },
                ),
                binds = buildMap {
                    claims?.get("vct")?.jsonPrimitive?.contentOrNull?.let { put("vct", it) }
                    claims?.get("iss")?.jsonPrimitive?.contentOrNull?.let { put("issuer", it) }
                    bound?.let { key -> Jose.thumbprint(key)?.let { put("cnf.jwk (holder key)", it) } }
                    put("committed digests (_sd)", committed.size.toString())
                    put("disclosures issued", sdJwt.disclosures.size.toString())
                    claims?.get("status")?.let { put("status reference", statusRef(it)) }
                },
                header = sdJwt.issuerJwt.header,
                payload = sdJwt.issuerJwt.payload,
                onWire = where,
                compact = sdJwt.issuerJwt.serialized,
                walletUnitId = exchange.walletUnitId,
            )
            crypto.record(
                flowId = exchange.flowId,
                operation = "disclose",
                actor = "issuer",
                artifact = "Disclosures",
                summary = "Every selectively disclosable claim travels as a salted preimage; the credential " +
                    "itself holds only their digests, which is what lets the wallet withhold any of them later",
                keys = emptyList(),
                binds = mapOf("claims" to sdJwt.disclosures.mapNotNull { it.name }.joinToString(", ")),
                payload = disclosureReport(sdJwt.disclosures, committed),
                onWire = where,
                walletUnitId = exchange.walletUnitId,
            )
            return
        }
        // An mdoc arrives base64/CBOR rather than JOSE; the inspector decodes it.
        if (!seen.add(raw.take(200))) return
        crypto.record(
            flowId = exchange.flowId,
            operation = "sign",
            actor = "issuer",
            artifact = "Issued credential (mso_mdoc)",
            summary = "Issuer returns a CBOR mdoc whose MSO is a COSE_Sign1 over the claim digests",
            binds = mapOf("encoding" to "CBOR / COSE, decoded in the credential inspector"),
            onWire = where,
            walletUnitId = exchange.walletUnitId,
        )
    }

    private fun requestObject(exchange: Exchange, compact: String, where: String) {
        val jws = fresh(compact) ?: return
        val claims = jws.claims
        crypto.record(
            flowId = exchange.flowId,
            operation = "sign",
            actor = "verifier",
            artifact = "Authorisation request object (JAR)",
            summary = "Verifier signs its request, so the wallet can authenticate who is asking " +
                "before deciding what to disclose",
            algorithm = jws.algorithm,
            keys = listOfNotNull(Jose.signerOf(jws, "verifier")),
            binds = buildMap {
                claims?.get("client_id")?.jsonPrimitive?.contentOrNull?.let { put("client id", it) }
                claims?.get("nonce")?.jsonPrimitive?.contentOrNull?.let { put("nonce (freshness)", it) }
                claims?.get("response_uri")?.jsonPrimitive?.contentOrNull?.let { put("response uri", it) }
                claims?.get("response_mode")?.jsonPrimitive?.contentOrNull?.let { put("response mode", it) }
                Jose.x5cSubject(jws)?.let { put("x5c subject", it) }
                claims?.get("dcql_query")?.let { query ->
                    put("requested claims", requestedClaims(query).joinToString(", ").ifBlank { "all" })
                }
            },
            header = jws.header,
            payload = jws.payload,
            onWire = where,
            compact = compact,
            walletUnitId = exchange.walletUnitId,
        )
    }

    private fun vpToken(exchange: Exchange, raw: String, where: String) {
        val sdJwt = Jose.parseSdJwt(raw) ?: return
        val kb = sdJwt.keyBindingJwt ?: return
        if (!seen.add(kb.serialized)) return
        val claims = kb.claims
        val committed = Jose.committedDigests(sdJwt.issuerJwt.payload)
        val disclosed = sdJwt.disclosures

        crypto.record(
            flowId = exchange.flowId,
            operation = "disclose",
            actor = "wallet",
            artifact = "Selective disclosure",
            summary = "Wallet forwards the issuer's signature untouched and releases only the " +
                "${disclosed.size} of ${committed.size} disclosures the verifier asked for — the " +
                "withheld claims remain digests the verifier cannot invert",
            binds = mapOf(
                "disclosed" to disclosed.mapNotNull { it.name }.joinToString(", ").ifBlank { "none" },
                "withheld" to (committed.size - disclosed.size).toString().plus(" digest(s)"),
            ),
            payload = disclosureReport(disclosed, committed),
            onWire = where,
            walletUnitId = exchange.walletUnitId,
        )

        crypto.record(
            flowId = exchange.flowId,
            operation = "sign",
            actor = "wallet",
            artifact = "Key binding JWT",
            summary = "Wallet signs with the device key the credential is bound to, over this verifier " +
                "and this nonce — the step that proves the presenter is the holder and not a replayer",
            algorithm = kb.algorithm,
            keys = listOfNotNull(
                sdJwt.issuerJwt.claims?.get("cnf")?.jsonObject?.get("jwk")
                    ?.let { Jose.keyRef(it, "device", storage = SOFTWARE) },
            ),
            binds = buildMap {
                claims?.get("aud")?.let { put("audience (verifier)", it.toString().trim('"')) }
                claims?.get("nonce")?.jsonPrimitive?.contentOrNull?.let { put("nonce (from verifier)", it) }
                claims?.get("sd_hash")?.jsonPrimitive?.contentOrNull?.let { put("sd_hash (binds this exact selection)", it) }
                claims?.get("iat")?.jsonPrimitive?.contentOrNull?.let { put("issued at", it) }
            },
            header = kb.header,
            payload = kb.payload,
            onWire = where,
            caveat = "Signed by a key in JVM heap. On a certified wallet unit this signature would require " +
                "user authentication against a WSCD, and the key could not leave the device.",
            compact = kb.serialized,
            walletUnitId = exchange.walletUnitId,
        )
    }

    private fun statusListToken(exchange: Exchange, compact: String, where: String) {
        val jws = fresh(compact) ?: return
        crypto.record(
            flowId = exchange.flowId,
            operation = "verify",
            actor = "issuer",
            artifact = "Status list token",
            summary = "A signed, compressed bitstring of revocation states; the reference to an index " +
                "in it is what makes an attestation or a credential revocable",
            algorithm = jws.algorithm,
            keys = listOfNotNull(Jose.signerOf(jws, "status-list")),
            binds = buildMap {
                jws.claims?.get("sub")?.jsonPrimitive?.contentOrNull?.let { put("list", it) }
                jws.claims?.get("exp")?.jsonPrimitive?.contentOrNull?.let { put("expires", it) }
            },
            header = jws.header,
            payload = jws.payload,
            onWire = where,
            compact = compact,
            walletUnitId = exchange.walletUnitId,
        )
    }

    // ----------------------------------------------------------------- helpers

    /**
     * Walks a `vp_token` and yields each presentation string in it.
     *
     * OpenID4VP 1.0 sends an object keyed by DCQL query id whose values are arrays of
     * presentations — not the bare credential a single-credential query might suggest.
     * The form field, the JSON member and the verifier's own echo all use that shape,
     * so all three go through here.
     */
    private fun eachPresentation(value: Any, action: (String) -> Unit) {
        val element = when (value) {
            is JsonElement -> value
            is String -> runCatching { lenientJson.parseToJsonElement(value) }.getOrNull()
                ?: return action(value)
            else -> return
        }
        when (element) {
            is JsonObject -> element.values.forEach { eachPresentation(it, action) }
            is JsonArray -> element.forEach { eachPresentation(it, action) }
            is JsonPrimitive -> element.contentOrNull?.let(action)
        }
    }

    /** Parses a compact JWS the first time it is seen, and null on every repeat. */
    private fun fresh(compact: String): Jose.Compact? {
        val trimmed = compact.trim()
        if (!Jose.looksCompact(trimmed)) return null
        if (!seen.add(trimmed)) return null
        return Jose.parse(trimmed)
    }

    /** Pairs each disclosure with the digest the issuer signed, so the link is visible. */
    private fun disclosureReport(disclosures: List<Jose.Disclosure>, committed: Set<String>): JsonElement =
        buildJsonArray {
            disclosures.forEach { disclosure ->
                addJsonObject {
                    put("claim", disclosure.name ?: "(array element)")
                    put("value", disclosure.value ?: JsonNull)
                    put("salt", disclosure.salt ?: "")
                    put("digest", disclosure.digest)
                    // A digest the issuer did not commit to would mean a forged disclosure.
                    put("matchesSignedDigest", disclosure.digest in committed)
                }
            }
        }

    private fun requestedClaims(query: JsonElement): List<String> = runCatching {
        (query as JsonObject)["credentials"]!!.jsonArray.flatMap { credential ->
            credential.jsonObject["claims"]?.jsonArray.orEmpty().mapNotNull { claim ->
                claim.jsonObject["path"]?.jsonArray?.joinToString(".") { it.jsonPrimitive.content }
            }
        }
    }.getOrElse { emptyList() }

    /** Flattens a token status list reference to `uri#index`. */
    private fun statusRef(status: JsonElement): String = runCatching {
        val list = status.jsonObject["status"]!!.jsonObject["status_list"]!!.jsonObject
        "${list["uri"]!!.jsonPrimitive.content}#${list["idx"]!!.jsonPrimitive.content}"
    }.getOrElse { status.toString().take(120) }

    private fun parseForm(body: String): Map<String, String> = body.split('&').mapNotNull { pair ->
        val index = pair.indexOf('=')
        if (index <= 0) return@mapNotNull null
        runCatching {
            URLDecoder.decode(pair.substring(0, index), Charsets.UTF_8) to
                URLDecoder.decode(pair.substring(index + 1), Charsets.UTF_8)
        }.getOrNull()
    }.toMap()

    private companion object {
        const val SOFTWARE = "software (JVM heap)"
        const val SELF_ATTESTED =
            "Signed by the testbed acting as its own wallet provider, under a self-signed certificate. " +
                "The authorisation server accepts it only because its trust validator is unconfigured."
    }
}
