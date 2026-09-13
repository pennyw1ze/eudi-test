package dev.eudi.testbed

/**
 * Runtime configuration. Everything has a default that matches the docker-compose
 * stack, so the wallet runs with no environment set at all.
 */
/**
 * A sample natural person the wallet can authenticate as during issuance. The chosen
 * subject decides which PID the issuer returns.
 */
@kotlinx.serialization.Serializable
data class SampleSubject(
    val username: String,
    /** Not serialised back to the console; the API only exposes username + displayName. */
    @kotlinx.serialization.Transient val password: String = "password",
    val displayName: String,
)

object Env {
    private fun env(key: String): String? = System.getenv(key)?.takeIf { it.isNotBlank() }

    /** Port the testbed (API + console UI) listens on. */
    val port: Int = env("TESTBED_PORT")?.toInt() ?: 4000

    /** Single origin the whole stack is published under by the gateway. */
    val publicOrigin: String = env("PUBLIC_ORIGIN") ?: "https://localhost"

    val issuerBase: String = env("ISSUER_BASE") ?: "$publicOrigin/pid-issuer"
    val verifierBase: String = env("VERIFIER_BASE") ?: "$publicOrigin/verifier"

    /**
     * The gateway uses a self-signed certificate, so the wallet has to accept it.
     * This is a local test harness; never reuse this setting anywhere real.
     */
    val trustAllTls: Boolean = (env("TRUST_ALL_TLS") ?: "true").toBoolean()

    /**
     * The realm's attestation-based client. `wallet-dev` is a plain public client, and
     * the issuer's credential endpoint rejects tokens obtained that way because they
     * carry no client_status claim.
     */
    val walletClientId: String = env("WALLET_CLIENT_ID") ?: "eudiw-abca"

    /**
     * Where the authorisation server sends the user back after login.
     *
     * Defaults to the wallet scheme that the upstream `wallet-dev` client already has
     * registered. Headless issuance never fetches this URI — it only reads the code out
     * of the redirect — so a custom scheme is fine and needs no Keycloak changes.
     *
     * Browser-based login does need a real http callback, which the upstream realm does
     * not register. `make keycloak-redirect` adds it, and then this should be set to
     * [browserRedirectUri].
     */
    val redirectUri: String = env("WALLET_REDIRECT_URI") ?: "eudi-openid4ci://authorize"

    /** The http callback used when the browser performs the login. */
    val browserRedirectUri: String = "http://localhost:$port/api/issuance/callback"

    /**
     * The pid-issuer only supports the authorization code flow, so issuance needs a
     * user login. These are the credentials of the sample user shipped in the
     * upstream Keycloak realm; the console can use them to complete the login
     * without a browser.
     */
    val autoLoginUser: String = env("AUTO_LOGIN_USER") ?: "tneal"
    val autoLoginPassword: String = env("AUTO_LOGIN_PASSWORD") ?: "password"

    /**
     * The sample natural persons available in the upstream Keycloak realm.
     *
     * The issuer builds the PID from the *authenticated* user's Keycloak attributes
     * (see the issuer's GetPidDataFromKeyCloak), so which subject a wallet unit logs in
     * as is exactly what determines the PID it receives. Issuing to different units under
     * different subjects is how two units end up holding two distinct PIDs — the
     * precondition for the presentation-time pooling attack, where two holders each
     * contribute a credential of their own.
     *
     * `tneal` ships in the upstream realm; the rest are added by
     * config/keycloak/pid-issuer-realm-users-1.json and share the password "password".
     */
    val sampleSubjects: List<SampleSubject> = listOf(
        SampleSubject(autoLoginUser, autoLoginPassword, "Tyler Neal"),
        SampleSubject("abianchi", "password", "Anna Bianchi"),
        SampleSubject("jkowalski", "password", "Jan Kowalski"),
    )

    /** The password to log [username] in with, if it is one of the known sample subjects. */
    fun passwordFor(username: String): String? =
        sampleSubjects.firstOrNull { it.username == username }?.password

    /**
     * The status list service that backs the key attestation's key_storage_status.
     * These match the API key and country configured for the containerised service.
     */
    val statusListApiKey: String = env("STATUS_LIST_API_KEY") ?: "aaa-bbb-ccc"
    val statusListCountry: String = env("STATUS_LIST_COUNTRY") ?: "FC"

    /**
     * Which of the verifier's configured intended uses to present under. The reference
     * verifier ships one, id "1" ("Person identification").
     */
    val verifierIntendedUseId: String = env("VERIFIER_INTENDED_USE_ID") ?: "1"

    /**
     * Where per-run trace directories and the participant list are written.
     *
     * Relative to the process working directory, which `make testbed` sets to the repo
     * root. Already git-ignored.
     */
    val sessionRoot: String = env("SESSION_ROOT") ?: "runs"
}
