package dev.eudi.testbed

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.util.Base64

/**
 * Decoding of the JOSE artefacts the protocol exchanges.
 *
 * Everything here is deliberately signature-agnostic: the point is to read what an
 * artefact claims and what it binds to, not to re-verify it. Verification is the
 * counterparty's job and the network log already shows whether they accepted it.
 */
object Jose {

    private val urlDecoder: Base64.Decoder = Base64.getUrlDecoder()

    /** A parsed compact JWS, with both protected parts decoded. */
    data class Compact(
        val header: JsonObject,
        val payload: JsonElement?,
        val serialized: String,
    ) {
        val algorithm: String? get() = header["alg"]?.jsonPrimitive?.contentOrNull
        val type: String? get() = header["typ"]?.jsonPrimitive?.contentOrNull
        val claims: JsonObject? get() = payload as? JsonObject
    }

    /** True for anything shaped like a compact JWS: three base64url segments. */
    fun looksCompact(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 3) return false
        return parts[0].isNotEmpty() && parts[2].isNotEmpty() &&
            parts.all { it.all { c -> c.isLetterOrDigit() || c == '-' || c == '_' } }
    }

    /** True for a compact JWE: five base64url segments. */
    fun looksEncrypted(value: String): Boolean {
        val parts = value.trim().split('.')
        return parts.size == 5 && parts[0].isNotEmpty() &&
            parts.all { it.all { c -> c.isLetterOrDigit() || c == '-' || c == '_' } }
    }

    /** The protected header of a compact JWE. The payload stays sealed, by definition. */
    fun encryptedHeader(value: String): JsonObject? =
        decodeSegment(value.trim().split('.').firstOrNull() ?: return null) as? JsonObject

    /** Decodes a compact JWS. Returns null when the value is not one. */
    fun parse(value: String): Compact? {
        val token = value.trim()
        if (!looksCompact(token)) return null
        val parts = token.split('.')
        val header = decodeSegment(parts[0]) as? JsonObject ?: return null
        // A JWS payload need not be JSON; a detached or binary payload is left null.
        return Compact(header, decodeSegment(parts[1]), token)
    }

    private fun decodeSegment(segment: String): JsonElement? = runCatching {
        lenientJson.parseToJsonElement(String(urlDecoder.decode(segment)))
    }.getOrNull()

    // ------------------------------------------------------------------- keys

    /**
     * RFC 7638 thumbprint of a JWK, base64url.
     *
     * Computed through Nimbus so the canonicalisation matches what every other party
     * in the ecosystem computes — a thumbprint that differs is worse than none.
     */
    fun thumbprint(jwk: JsonElement): String? = runCatching {
        JWK.parse(jwk.toString()).computeThumbprint().toString()
    }.getOrNull()

    /** Describes a JWK as a [KeyRef], resolving its thumbprint. */
    fun keyRef(jwk: JsonElement, role: String, storage: String? = null): KeyRef? {
        val obj = jwk as? JsonObject ?: return null
        val tp = thumbprint(obj) ?: return null
        return KeyRef(
            role = role,
            thumbprint = tp,
            kty = obj["kty"]?.jsonPrimitive?.contentOrNull,
            crv = obj["crv"]?.jsonPrimitive?.contentOrNull,
            kid = obj["kid"]?.jsonPrimitive?.contentOrNull,
            storage = storage,
        )
    }

    /**
     * The signing key of a JWS, when the header carries one.
     *
     * `jwk` gives it directly; `x5c` gives a certificate whose public key is the signer.
     * Neither being present is normal — the verifier is then expected to know the key
     * from metadata, and the thumbprint has to come from elsewhere.
     */
    fun signerOf(compact: Compact, role: String, storage: String? = null): KeyRef? {
        compact.header["jwk"]?.let { return keyRef(it, role, storage) }
        val leaf = compact.header["x5c"]?.jsonArray?.firstOrNull()?.jsonPrimitive?.contentOrNull
        if (leaf != null) {
            val fromCert = runCatching {
                val bytes = Base64.getDecoder().decode(leaf)
                val cert = java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(bytes.inputStream()) as java.security.cert.X509Certificate
                JWK.parseFromPEMEncodedX509Cert(
                    "-----BEGIN CERTIFICATE-----\n" +
                        Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded) +
                        "\n-----END CERTIFICATE-----",
                )
            }.getOrNull()
            if (fromCert != null) {
                return KeyRef(
                    role = role,
                    thumbprint = runCatching { fromCert.computeThumbprint().toString() }.getOrNull() ?: return null,
                    kty = fromCert.keyType?.value,
                    crv = (fromCert as? com.nimbusds.jose.jwk.ECKey)?.curve?.name,
                    storage = storage,
                )
            }
        }
        return null
    }

    /** The subject name of the leaf certificate in an `x5c` header, for display. */
    fun x5cSubject(compact: Compact): String? = runCatching {
        val leaf = compact.header["x5c"]?.jsonArray?.firstOrNull()?.jsonPrimitive?.content ?: return null
        val cert = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(Base64.getDecoder().decode(leaf).inputStream())
            as java.security.cert.X509Certificate
        cert.subjectX500Principal.name
    }.getOrNull()

    // ----------------------------------------------------------------- SD-JWT

    /** The three parts of an SD-JWT: issuer-signed JWT, disclosures, optional KB-JWT. */
    data class SdJwt(
        val issuerJwt: Compact,
        val disclosures: List<Disclosure>,
        val keyBindingJwt: Compact?,
    )

    /**
     * One disclosure: the salted preimage of a digest in the issuer-signed payload.
     *
     * [digest] is what the issuer actually signed — the disclosure itself is never in
     * the credential, only its hash — so it is the value that proves selective
     * disclosure is sound rather than cosmetic.
     */
    data class Disclosure(
        val encoded: String,
        val digest: String,
        val salt: String?,
        val name: String?,
        val value: JsonElement?,
    )

    /** Splits an SD-JWT presentation or issuance. Null when it is not one. */
    fun parseSdJwt(raw: String): SdJwt? {
        if ('~' !in raw) return null
        val parts = raw.split('~')
        val issuer = parse(parts.first()) ?: return null
        val trailing = parts.drop(1)
        val kb = trailing.lastOrNull()?.takeIf { looksCompact(it) }?.let { parse(it) }
        val disclosureParts = if (kb != null) trailing.dropLast(1) else trailing
        return SdJwt(
            issuerJwt = issuer,
            disclosures = disclosureParts.filter { it.isNotBlank() }.map { decodeDisclosure(it) },
            keyBindingJwt = kb,
        )
    }

    fun decodeDisclosure(encoded: String): Disclosure {
        val array = runCatching {
            lenientJson.parseToJsonElement(String(urlDecoder.decode(encoded))).jsonArray
        }.getOrNull()
        // [salt, name, value] for an object member, [salt, value] for an array element.
        val salt = array?.getOrNull(0)?.jsonPrimitive?.contentOrNull
        val name = if (array != null && array.size >= 3) array[1].jsonPrimitive.contentOrNull else null
        val value = array?.lastOrNull()
        return Disclosure(
            encoded = encoded,
            digest = digest(encoded),
            salt = salt,
            name = name,
            value = if (array != null && array.size >= 2) value else null,
        )
    }

    /** The `_sd` digest of a disclosure: base64url(SHA-256(ascii(disclosure))). */
    fun digest(encoded: String): String = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(encoded.toByteArray(Charsets.US_ASCII)))

    /** Digests the issuer committed to in the payload, including nested `_sd` arrays. */
    fun committedDigests(payload: JsonElement?): Set<String> {
        val found = mutableSetOf<String>()
        fun walk(node: JsonElement?) {
            when (node) {
                is JsonObject -> node.forEach { (key, value) ->
                    if (key == "_sd") value.jsonArray.forEach { d -> d.jsonPrimitive.contentOrNull?.let(found::add) }
                    else walk(value)
                }
                is JsonArray -> node.forEach { element ->
                    // Array elements are hidden as {"...": "<digest>"}.
                    ((element as? JsonObject)?.get("..."))?.jsonPrimitive?.contentOrNull?.let(found::add)
                    walk(element)
                }
                else -> Unit
            }
        }
        walk(payload)
        return found
    }
}
