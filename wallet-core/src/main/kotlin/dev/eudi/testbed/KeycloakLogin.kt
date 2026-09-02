package dev.eudi.testbed

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*

/**
 * Completes the authorisation code flow without a browser.
 *
 * The reference pid-issuer supports only the authorization code grant, so issuance
 * always involves a user login at Keycloak. A real wallet opens a browser for this.
 * For an automated testbed that would make every run manual, so this drives the
 * Keycloak login form directly: fetch the login page, post the credentials to the
 * form's action, and read the authorization code out of the redirect.
 *
 * It is deliberately the only screen-scraping in the project, and it is confined to
 * the sample realm shipped upstream.
 */
object KeycloakLogin {

    data class Callback(val code: String, val state: String?)

    private val formActionPattern = Regex("""<form[^>]*action="([^"]+)"[^>]*>""", RegexOption.IGNORE_CASE)

    suspend fun authorize(
        client: HttpClient,
        authorizationUrl: String,
        username: String,
        password: String,
        sink: TraceSink,
        flowId: String,
    ): Callback {
        sink.step(flowId, "Opening authorisation endpoint as a browser would", actor = "authorization-server")

        var response = client.get(authorizationUrl)

        // The authorisation endpoint may bounce once or twice before the login form.
        var hops = 0
        while (response.status.isRedirect() && hops++ < 5) {
            val next = response.headers[HttpHeaders.Location] ?: break
            response = client.get(resolve(authorizationUrl, next))
        }

        val page = response.bodyAsText()
        val action = formActionPattern.find(page)?.groupValues?.get(1)?.replace("&amp;", "&")
            ?: error("Could not find the Keycloak login form. Response was HTTP ${response.status.value}.")

        sink.step(flowId, "Submitting credentials for user '$username'", actor = "authorization-server")

        val submitted = client.submitForm(
            url = resolve(authorizationUrl, action),
            formParameters = parameters {
                append("username", username)
                append("password", password)
                append("credentialId", "")
            },
        )

        if (!submitted.status.isRedirect()) {
            error(
                "Login did not produce a redirect (HTTP ${submitted.status.value}). " +
                    "The user may have a required action pending in Keycloak.",
            )
        }

        val location = submitted.headers[HttpHeaders.Location]
            ?: error("Login redirect carried no Location header")
        val query = Url(location).parameters
        val code = query["code"]
            ?: error("Authorisation server returned no code. error=${query["error"]} ${query["error_description"] ?: ""}")

        sink.step(flowId, "Received authorisation code via redirect", actor = "authorization-server")
        return Callback(code, query["state"])
    }

    private fun HttpStatusCode.isRedirect(): Boolean = value in 300..399

    private fun resolve(base: String, candidate: String): String =
        if (candidate.startsWith("http://") || candidate.startsWith("https://")) candidate
        else URLBuilder(base).apply { set(path = candidate) }.buildString()
}
