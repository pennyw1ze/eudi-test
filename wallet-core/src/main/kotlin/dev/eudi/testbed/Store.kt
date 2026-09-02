package dev.eudi.testbed

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

    fun add(configurationId: String, format: String, raw: String, issuer: String): StoredCredential {
        val credential = StoredCredential(
            id = UUID.randomUUID().toString(),
            configurationId = configurationId,
            format = format,
            raw = raw,
            issuedAt = Instant.now().toString(),
            issuer = issuer,
        )
        credentials[credential.id] = credential
        return credential
    }

    fun all(): List<StoredCredential> = credentials.values.sortedBy { it.issuedAt }
    fun get(id: String): StoredCredential? = credentials[id]
    fun remove(id: String): Boolean = credentials.remove(id) != null
    fun clear() = credentials.clear()
}
