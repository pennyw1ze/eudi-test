package dev.eudi.testbed

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

/**
 * A key as it appears in the protocol, identified by its RFC 7638 thumbprint.
 *
 * The thumbprint is what makes the binding chain legible. The same device key turns up
 * in the key attestation's `attested_keys`, in the issued credential's `cnf.jwk` and as
 * the signer of the key binding JWT; only the thumbprint proves those three are one key,
 * and that chain is the whole cryptographic argument of OpenID4VCI + OpenID4VP.
 */
@Serializable
data class KeyRef(
    /** device, wallet-provider, dpop, client-pop, issuer, verifier … */
    val role: String,
    /** RFC 7638 thumbprint, base64url. Stable across every representation of the key. */
    val thumbprint: String,
    val kty: String? = null,
    val crv: String? = null,
    val kid: String? = null,
    /**
     * Where the private half lives. Everything this testbed holds is software-backed;
     * a certified wallet unit would name its WSCD here. See the LoA note in the README.
     */
    val storage: String? = null,
)

/**
 * One cryptographic operation in the protocol.
 *
 * This is deliberately not an HTTP record. The network log answers "which bytes moved";
 * this answers "who proved what to whom, over which key, bound to which values". Most
 * events are recovered from the wire by [CryptoScanner] — the JOSE artefacts really
 * exchanged — and the rest are emitted directly where the operation never reaches the
 * network, such as key generation.
 */
@Serializable
data class CryptoEvent(
    val seq: Long,
    val at: String,
    val flowId: String,
    /** keygen | sign | verify | disclose | bind */
    val operation: String,
    /** The party that performed it. */
    val actor: String,
    /** The artefact, under the name the specification gives it. */
    val artifact: String,
    /** One line on what this step achieves cryptographically. */
    val summary: String,
    val algorithm: String? = null,
    /** Keys involved, signer first. */
    val keys: List<KeyRef> = emptyList(),
    /** What the artefact commits to: audience, nonce, digest, expiry, status reference. */
    val binds: Map<String, String> = emptyMap(),
    val header: JsonElement? = null,
    val payload: JsonElement? = null,
    /** Where it was observed, so an event can be traced back to the network log. */
    val onWire: String? = null,
    /** Stated where the testbed's real assurance differs from what the artefact claims. */
    val caveat: String? = null,
    /** The compact serialization, for offline verification of the saved trace. */
    val compact: String? = null,
    /** The wallet unit this belongs to, when the flow has one. */
    val walletUnitId: String? = null,
)

/**
 * Bounded in-memory log of cryptographic events, mirrored to the session file.
 *
 * Mirroring happens on emit rather than at shutdown so a crashed or killed run still
 * leaves a complete trace behind — which is the point of recording one.
 */
class CryptoSink(
    private val session: SessionLog,
    private val capacity: Int = 4000,
) {
    private val seq = AtomicLong(0)
    private val events = ArrayDeque<CryptoEvent>()

    fun next(): Long = seq.incrementAndGet()

    fun emit(event: CryptoEvent) {
        synchronized(events) {
            events.addLast(event)
            while (events.size > capacity) events.removeFirst()
        }
        session.appendCrypto(event)
    }

    fun since(cursor: Long, flowId: String? = null): List<CryptoEvent> = synchronized(events) {
        events.filter { it.seq > cursor && (flowId == null || it.flowId == flowId) }
    }

    /** Every distinct key seen so far, so the console can colour the binding chain. */
    fun keys(): List<KeyRef> = synchronized(events) {
        events.flatMap { it.keys }.distinctBy { it.thumbprint }
    }

    fun record(
        flowId: String,
        operation: String,
        actor: String,
        artifact: String,
        summary: String,
        algorithm: String? = null,
        keys: List<KeyRef> = emptyList(),
        binds: Map<String, String> = emptyMap(),
        header: JsonElement? = null,
        payload: JsonElement? = null,
        onWire: String? = null,
        caveat: String? = null,
        compact: String? = null,
        walletUnitId: String? = null,
    ) = emit(
        CryptoEvent(
            seq = next(),
            at = Instant.now().toString(),
            flowId = flowId,
            operation = operation,
            actor = actor,
            artifact = artifact,
            summary = summary,
            algorithm = algorithm,
            keys = keys,
            binds = binds,
            header = header,
            payload = payload,
            onWire = onWire,
            caveat = caveat,
            compact = compact,
            walletUnitId = walletUnitId,
        ),
    )
}
