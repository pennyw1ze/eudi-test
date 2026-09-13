package dev.eudi.testbed

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** An OpenID4VCI credential issuer the wallet can be pointed at. */
@Serializable
data class IssuerRef(
    val id: String,
    val label: String,
    /** Credential issuer identifier; metadata is discovered under it. */
    val base: String,
    /** The client id the authorisation server knows this wallet by. */
    val clientId: String = Env.walletClientId,
    /** Sample-realm credentials used by headless issuance. */
    val loginUser: String = Env.autoLoginUser,
    val loginPassword: String = Env.autoLoginPassword,
)

/**
 * What the console is told about an issuer.
 *
 * The stored login password is deliberately not part of it: it has to be persisted to
 * drive headless issuance, but nothing in the UI needs it back, and an API that hands
 * out a password it was given is a habit worth not forming even in a test harness.
 */
@Serializable
data class IssuerView(
    val id: String,
    val label: String,
    val base: String,
    val clientId: String,
    val loginUser: String,
)

fun IssuerRef.view(): IssuerView = IssuerView(id, label, base, clientId, loginUser)

/** An OpenID4VP verifier the wallet can present to. */
@Serializable
data class VerifierRef(
    val id: String,
    val label: String,
    val base: String,
    /**
     * Which configured Wallet Relying Party Intended Use to present under. The reference
     * verifier attaches its registration certificate from this and refuses without one.
     */
    val intendedUseId: String = Env.verifierIntendedUseId,
)

/**
 * A wallet unit: one instance's key material and the credentials bound to it.
 *
 * Separating these is what makes more than one unit meaningful. Credentials are bound
 * to a device key by `cnf`, so a credential issued to one unit cannot be presented by
 * another — running two units side by side is the cheapest way to see that binding
 * actually hold.
 */
class WalletUnit(
    val id: String,
    @Volatile var label: String,
    val keys: WalletKeys,
    val store: CredentialStore = CredentialStore(),
    val createdAt: Instant = Instant.now(),
)

@Serializable
data class WalletUnitInfo(
    val id: String,
    val label: String,
    val createdAt: String,
    val credentials: Int,
    val keys: List<KeyRef>,
)

@Serializable
private data class PersistedParticipants(
    val issuers: List<IssuerRef> = emptyList(),
    val verifiers: List<VerifierRef> = emptyList(),
)

/**
 * The participants the console knows about.
 *
 * Issuers and verifiers are configuration and persist across runs — retyping a URL
 * every restart is friction with no upside. Wallet units are not persisted: they are
 * key material plus held credentials, and a testbed that resurrected yesterday's keys
 * would quietly invalidate the "fresh session" the trace file promises.
 */
class Registry(private val crypto: CryptoSink) {

    private val walletUnits = ConcurrentHashMap<String, WalletUnit>()
    private val issuers = ConcurrentHashMap<String, IssuerRef>()
    private val verifiers = ConcurrentHashMap<String, VerifierRef>()

    private val order = mutableListOf<String>()
    private val file: Path = Path.of(Env.sessionRoot, "participants.json")
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true; encodeDefaults = true }

    init {
        restore()
        if (issuers.isEmpty()) {
            addIssuer("Reference issuer", Env.issuerBase, persist = false)
        }
        if (verifiers.isEmpty()) {
            addVerifier("Reference verifier", Env.verifierBase, persist = false)
        }
        addWalletUnit("Wallet unit 1")
    }

    // ----------------------------------------------------------- wallet units

    fun walletUnits(): List<WalletUnit> = synchronized(order) { order.mapNotNull { walletUnits[it] } }

    fun walletUnit(id: String?): WalletUnit =
        (id?.let { walletUnits[it] } ?: walletUnits().firstOrNull())
            ?: error("No wallet unit exists; add one first")

    fun addWalletUnit(label: String): WalletUnit {
        val id = "wu-" + UUID.randomUUID().toString().take(8)
        // Key generation is a cryptographic event in its own right and never reaches the
        // wire, so it is recorded here rather than recovered by the scanner.
        val unit = WalletUnit(id = id, label = label, keys = WalletKeys(unitId = id, crypto = crypto))
        walletUnits[id] = unit
        synchronized(order) { order.add(id) }
        return unit
    }

    fun renameWalletUnit(id: String, label: String): Boolean =
        walletUnits[id]?.also { it.label = label } != null

    fun removeWalletUnit(id: String): Boolean {
        if (walletUnits.size <= 1) error("The last wallet unit cannot be removed")
        synchronized(order) { order.remove(id) }
        return walletUnits.remove(id) != null
    }

    fun info(unit: WalletUnit) = WalletUnitInfo(
        id = unit.id,
        label = unit.label,
        createdAt = unit.createdAt.toString(),
        credentials = unit.store.all().size,
        keys = unit.keys.describe(),
    )

    // ---------------------------------------------------------------- issuers

    fun issuers(): List<IssuerRef> = issuers.values.sortedBy { it.label }

    fun issuer(id: String?): IssuerRef =
        (id?.let { issuers[it] } ?: issuers().firstOrNull())
            ?: error("No issuer is configured; add one first")

    fun addIssuer(
        label: String,
        base: String,
        clientId: String = Env.walletClientId,
        loginUser: String = Env.autoLoginUser,
        loginPassword: String = Env.autoLoginPassword,
        persist: Boolean = true,
    ): IssuerRef {
        val ref = IssuerRef(
            id = "iss-" + UUID.randomUUID().toString().take(8),
            label = label,
            base = base.trimEnd('/'),
            clientId = clientId,
            loginUser = loginUser,
            loginPassword = loginPassword,
        )
        issuers[ref.id] = ref
        if (persist) save()
        return ref
    }

    fun removeIssuer(id: String): Boolean = (issuers.remove(id) != null).also { if (it) save() }

    // -------------------------------------------------------------- verifiers

    fun verifiers(): List<VerifierRef> = verifiers.values.sortedBy { it.label }

    fun verifier(id: String?): VerifierRef =
        (id?.let { verifiers[it] } ?: verifiers().firstOrNull())
            ?: error("No verifier is configured; add one first")

    fun addVerifier(
        label: String,
        base: String,
        intendedUseId: String = Env.verifierIntendedUseId,
        persist: Boolean = true,
    ): VerifierRef {
        val ref = VerifierRef(
            id = "vrf-" + UUID.randomUUID().toString().take(8),
            label = label,
            base = base.trimEnd('/'),
            intendedUseId = intendedUseId,
        )
        verifiers[ref.id] = ref
        if (persist) save()
        return ref
    }

    fun removeVerifier(id: String): Boolean = (verifiers.remove(id) != null).also { if (it) save() }

    // ------------------------------------------------------------ persistence

    private fun restore() {
        val text = runCatching { Files.readString(file) }.getOrNull() ?: return
        val stored = runCatching { json.decodeFromString(PersistedParticipants.serializer(), text) }.getOrNull()
            ?: return
        stored.issuers.forEach { issuers[it.id] = it }
        stored.verifiers.forEach { verifiers[it.id] = it }
    }

    private fun save() {
        runCatching {
            Files.createDirectories(file.parent)
            Files.writeString(
                file,
                json.encodeToString(
                    PersistedParticipants.serializer(),
                    PersistedParticipants(issuers(), verifiers()),
                ),
            )
        }
    }
}
