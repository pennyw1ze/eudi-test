package dev.eudi.testbed

import io.ktor.client.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

val lenientJson = Json {
    ignoreUnknownKeys = true
    isLenient = true
    encodeDefaults = true
    explicitNulls = false
}

/**
 * Accepts the gateway's self-signed certificate.
 *
 * This exists only because the testbed terminates TLS with a certificate it
 * generated itself. It disables certificate validation for every host this client
 * talks to, which is acceptable for a throwaway local stack and nowhere else.
 */
private val insecureTrustManager = object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

/** A client for health probes, deliberately untraced so it does not pollute the log. */
fun plainHttpClient(): HttpClient = HttpClient(OkHttp) {
    expectSuccess = false
    followRedirects = false
    engine {
        if (Env.trustAllTls) {
            config {
                val sslContext = SSLContext.getInstance("TLS").apply {
                    init(null, arrayOf(insecureTrustManager), SecureRandom())
                }
                sslSocketFactory(sslContext.socketFactory, insecureTrustManager)
                hostnameVerifier { _, _ -> true }
            }
        }
    }
    install(ContentNegotiation) { json(lenientJson) }
}

/**
 * An HTTP client bound to a single flow, so every exchange it records is already
 * correlated. Flows are short-lived, so a client per flow is cheaper than threading
 * a correlation id through the EUDI libraries.
 */
fun tracedHttpClient(
    flowId: String,
    sink: TraceSink,
    /** The authorisation code login needs a cookie jar to get through Keycloak. */
    withCookies: Boolean = false,
): HttpClient = HttpClient(OkHttp) {
    expectSuccess = false
    followRedirects = false
    engine {
        addInterceptor(TracingInterceptor(flowId, sink))
        if (Env.trustAllTls) {
            config {
                val sslContext = SSLContext.getInstance("TLS").apply {
                    init(null, arrayOf(insecureTrustManager), SecureRandom())
                }
                sslSocketFactory(sslContext.socketFactory, insecureTrustManager)
                hostnameVerifier { _, _ -> true }
            }
        }
    }
    install(ContentNegotiation) { json(lenientJson) }
    if (withCookies) install(HttpCookies)
}
