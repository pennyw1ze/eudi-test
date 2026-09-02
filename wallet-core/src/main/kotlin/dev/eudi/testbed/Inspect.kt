package dev.eudi.testbed

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import kotlinx.serialization.json.*
import java.util.Base64

/**
 * Decodes issued credentials into something readable.
 *
 * This is the half of "tracking" that the protocol log cannot show: the log proves
 * which bytes moved, this shows what those bytes actually claim.
 */
object Inspector {

    private val base64Url: Base64.Decoder = Base64.getUrlDecoder()

    fun inspect(credential: StoredCredential): JsonObject = buildJsonObject {
        put("id", credential.id)
        put("format", credential.format)
        put("configurationId", credential.configurationId)
        put("issuedAt", credential.issuedAt)
        put("issuer", credential.issuer)
        val decoded = runCatching {
            when {
                credential.format.contains("sd-jwt") || credential.raw.contains('~') -> decodeSdJwtVc(credential.raw)
                credential.format.contains("mdoc") -> decodeMdoc(credential.raw)
                credential.raw.count { it == '.' } == 2 -> buildJsonObject { put("jwt", decodeJwt(credential.raw)) }
                else -> buildJsonObject { put("note", JsonPrimitive("unrecognised credential encoding")) }
            }
        }
        put("decoded", decoded.getOrElse { buildJsonObject { put("error", JsonPrimitive(it.message ?: "decode failed")) } })
    }

    // ---------------------------------------------------------------- SD-JWT VC

    /**
     * An SD-JWT VC is `<issuer-signed JWT>~<disclosure>~...~[<key binding JWT>]`.
     * Each disclosure is a base64url JSON array: `[salt, name, value]` for an object
     * member, `[salt, value]` for an array element.
     */
    fun decodeSdJwtVc(raw: String): JsonObject {
        val parts = raw.split('~')
        val issuerJwt = parts.first()
        val trailing = parts.drop(1)
        // A trailing empty segment means "no key binding JWT present".
        val keyBinding = trailing.lastOrNull()?.takeIf { it.count { c -> c == '.' } == 2 }
        val disclosureParts = if (keyBinding != null) trailing.dropLast(1) else trailing

        return buildJsonObject {
            put("type", JsonPrimitive("sd-jwt-vc"))
            put("issuerSignedJwt", decodeJwt(issuerJwt))
            putJsonArray("disclosures") {
                disclosureParts.filter { it.isNotBlank() }.forEach { disclosure ->
                    add(decodeDisclosure(disclosure))
                }
            }
            if (keyBinding != null) put("keyBindingJwt", decodeJwt(keyBinding))
        }
    }

    private fun decodeDisclosure(disclosure: String): JsonObject = buildJsonObject {
        put("encoded", JsonPrimitive(disclosure))
        val decoded = runCatching {
            Json.parseToJsonElement(String(base64Url.decode(disclosure))).jsonArray
        }.getOrNull()
        if (decoded == null) {
            put("error", JsonPrimitive("not a valid disclosure"))
            return@buildJsonObject
        }
        put("salt", decoded[0])
        when (decoded.size) {
            3 -> {
                put("claim", decoded[1])
                put("value", decoded[2])
            }
            2 -> put("value", decoded[1])
            else -> put("raw", decoded)
        }
    }

    fun decodeJwt(jwt: String): JsonObject = buildJsonObject {
        val segments = jwt.split('.')
        require(segments.size == 3) { "not a compact JWS" }
        put("header", Json.parseToJsonElement(String(base64Url.decode(segments[0]))))
        put("payload", Json.parseToJsonElement(String(base64Url.decode(segments[1]))))
        put("signature", JsonPrimitive(segments[2]))
    }

    // ---------------------------------------------------------------- mso_mdoc

    /**
     * An `mso_mdoc` credential is base64url CBOR holding an IssuerSigned structure:
     * the disclosed items per namespace, plus a COSE_Sign1 Mobile Security Object.
     */
    fun decodeMdoc(raw: String): JsonObject {
        val cbor = CBORObject.DecodeFromBytes(base64Url.decode(raw))
        return buildJsonObject {
            put("type", JsonPrimitive("mso_mdoc"))
            put("issuerSigned", cborToJson(cbor))
        }
    }

    /**
     * CBOR has no faithful JSON projection, so this keeps the parts that matter for
     * inspection: byte strings become base64, and tag 24 (an embedded CBOR data item,
     * which is how each IssuerSignedItem is wrapped) is decoded rather than shown as
     * an opaque blob.
     */
    private fun cborToJson(cbor: CBORObject): JsonElement {
        if (cbor.isTagged && cbor.HasMostOuterTag(24)) {
            val inner = runCatching { CBORObject.DecodeFromBytes(cbor.Untag().GetByteString()) }.getOrNull()
            if (inner != null) return cborToJson(inner)
        }
        val untagged = if (cbor.isTagged) cbor.Untag() else cbor
        return when (untagged.type) {
            CBORType.Map -> buildJsonObject {
                untagged.keys.forEach { key ->
                    put(key.let { if (it.type == CBORType.TextString) it.AsString() else it.ToJSONString() }, cborToJson(untagged[key]))
                }
            }
            CBORType.Array -> buildJsonArray { untagged.values.forEach { add(cborToJson(it)) } }
            CBORType.TextString -> JsonPrimitive(untagged.AsString())
            CBORType.Boolean -> JsonPrimitive(untagged.AsBoolean())
            // Very large integers do not fit a Long; fall back to their textual form.
            CBORType.Integer -> runCatching { JsonPrimitive(untagged.AsInt64Value()) }
                .getOrElse { JsonPrimitive(untagged.ToJSONString()) }
            CBORType.FloatingPoint -> JsonPrimitive(untagged.AsDoubleValue())
            CBORType.ByteString -> JsonPrimitive(
                Base64.getUrlEncoder().withoutPadding().encodeToString(untagged.GetByteString()),
            )
            else -> JsonPrimitive(untagged.ToJSONString())
        }
    }
}
