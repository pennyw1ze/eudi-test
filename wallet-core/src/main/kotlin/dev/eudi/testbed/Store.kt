package dev.eudi.testbed

import com.nimbusds.jose.jwk.ECKey
import kotlinx.serialization.Serializable
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

@Serializable
data class StoredCredential(
    val id: String,
    val configurationId: String,
    val format: String,
    val raw: String,
    val issuedAt: String,
    val issuer: String,
)

/**
 * The wallet's credential store. In memory on purpose: a testbed should start from a
 * clean holder on every run, so state cannot leak between experiments.
 */
class CredentialStore {
    private val credentials = ConcurrentHashMap<String, StoredCredential>()

    /**
     * The device key each stored credential is bound to (`cnf`), by credential id.
     *
     * Kept out of [StoredCredential] because that is serialized to the console API, and a
     * private key must never leave the wallet. With batch issuance every copy binds to a
     * *different* key, so the key can no longer be read off the wallet unit; it has to travel
     * with the credential that was bound to it, or the key-binding JWT at presentation would
     * be signed by the wrong key.
     */
    private val deviceKeys = ConcurrentHashMap<String, ECKey>()

    fun add(
        configurationId: String,
        format: String,
        raw: String,
        issuer: String,
        deviceKey: ECKey? = null,
    ): StoredCredential {
        val credential = StoredCredential(
            id = UUID.randomUUID().toString(),
            configurationId = configurationId,
            format = format,
            raw = raw,
            issuedAt = Instant.now().toString(),
            issuer = issuer,
        )
        credentials[credential.id] = credential
        if (deviceKey != null) deviceKeys[credential.id] = deviceKey
        return credential
    }

    /** The private device key credential [id] is bound to, if one was recorded at issuance. */
    fun deviceKeyFor(id: String): ECKey? = deviceKeys[id]

    fun all(): List<StoredCredential> = credentials.values.sortedBy { it.issuedAt }
    fun get(id: String): StoredCredential? = credentials[id]
    fun remove(id: String): Boolean {
        deviceKeys.remove(id)
        return credentials.remove(id) != null
    }
    fun clear() {
        credentials.clear()
        deviceKeys.clear()
    }
}
