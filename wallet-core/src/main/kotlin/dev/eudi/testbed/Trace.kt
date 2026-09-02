package dev.eudi.testbed

import kotlinx.serialization.Serializable
import okhttp3.Interceptor
import okhttp3.Response
import okio.Buffer
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

/**
 * One observed protocol event. The console renders these as the timeline of a flow.
 */
@Serializable
data class TraceEvent(
    val seq: Long,
    val at: String,
    val flowId: String,
    /** "http" for an observed exchange, "step" for a narrative marker, "error" for a failure. */
    val kind: String,
    /** Who the wallet was talking to: issuer, authorization-server, verifier, wallet. */
    val actor: String,
    val method: String? = null,
    val url: String? = null,
    val status: Int? = null,
    val durationMs: Long? = null,
    val requestHeaders: Map<String, String>? = null,
    val requestBody: String? = null,
    val responseHeaders: Map<String, String>? = null,
    val responseBody: String? = null,
    val note: String? = null,
)

/**
 * Bounded, in-memory event log. The console polls it with a cursor, so events are
 * never removed while a flow is still being read, only once the buffer wraps.
 */
class TraceSink(private val capacity: Int = 2000) {
    private val seq = AtomicLong(0)
    private val events = ArrayDeque<TraceEvent>()

    fun emit(event: TraceEvent) = synchronized(events) {
        events.addLast(event)
        while (events.size > capacity) events.removeFirst()
    }

    fun next(): Long = seq.incrementAndGet()

    fun since(cursor: Long, flowId: String? = null): List<TraceEvent> = synchronized(events) {
        events.filter { it.seq > cursor && (flowId == null || it.flowId == flowId) }
    }

    fun step(flowId: String, note: String, actor: String = "wallet") = emit(
        TraceEvent(
            seq = next(),
            at = Instant.now().toString(),
            flowId = flowId,
            kind = "step",
            actor = actor,
            note = note,
        ),
    )

    fun error(flowId: String, note: String) = emit(
        TraceEvent(
            seq = next(),
            at = Instant.now().toString(),
            flowId = flowId,
            kind = "error",
            actor = "wallet",
            note = note,
        ),
    )
}

/** Guess which participant a URL belongs to, so the timeline can be colour-coded. */
internal fun actorOf(url: String): String = when {
    "/pid-issuer" in url || "/token_status_list" in url -> "issuer"
    "/idp" in url -> "authorization-server"
    "/verifier" in url -> "verifier"
    else -> "other"
}

/**
 * Records every request/response the wallet makes.
 *
 * This sits in OkHttp rather than in a Ktor plugin on purpose: at this level both
 * bodies are available without interfering with how the EUDI libraries consume the
 * response, and `peekBody` leaves the real body untouched for the caller.
 */
class TracingInterceptor(
    private val flowId: String,
    private val sink: TraceSink,
    private val maxBody: Long = 256L * 1024,
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val url = request.url.toString()
        val requestBody = request.body?.let { body ->
            runCatching { Buffer().also { body.writeTo(it) }.readUtf8() }.getOrNull()
        }
        val startedAt = System.nanoTime()

        val response = try {
            chain.proceed(request)
        } catch (failure: Exception) {
            sink.emit(
                TraceEvent(
                    seq = sink.next(),
                    at = Instant.now().toString(),
                    flowId = flowId,
                    kind = "error",
                    actor = actorOf(url),
                    method = request.method,
                    url = url,
                    durationMs = (System.nanoTime() - startedAt) / 1_000_000,
                    requestHeaders = request.headers.toMap(),
                    requestBody = requestBody,
                    note = "transport failure: ${failure.message}",
                ),
            )
            throw failure
        }

        sink.emit(
            TraceEvent(
                seq = sink.next(),
                at = Instant.now().toString(),
                flowId = flowId,
                kind = "http",
                actor = actorOf(url),
                method = request.method,
                url = url,
                status = response.code,
                durationMs = (System.nanoTime() - startedAt) / 1_000_000,
                requestHeaders = request.headers.toMap(),
                requestBody = requestBody,
                responseHeaders = response.headers.toMap(),
                responseBody = runCatching { response.peekBody(maxBody).string() }.getOrNull(),
            ),
        )
        return response
    }

    private fun okhttp3.Headers.toMap(): Map<String, String> =
        names().associateWith { name -> values(name).joinToString(", ") }
}
