package dev.eudi.testbed

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.UUID

@Serializable
data class SessionInfo(
    val id: String,
    val startedAt: String,
    val directory: String,
    val cryptoTraceFile: String,
    val networkTraceFile: String,
    val cryptoEvents: Long,
    val networkEvents: Long,
)

/**
 * The on-disk record of one run.
 *
 * A fresh directory per process, because a testbed run is the unit people compare:
 * mixing two runs into one file loses the only boundary that matters. Events are
 * appended as they happen rather than dumped at shutdown, so a run that is killed or
 * crashes still leaves everything it managed to observe.
 *
 * JSON Lines, not JSON: an append-only file stays valid after every write, and the
 * result is greppable and streamable without a parser.
 */
class SessionLog(root: Path = Path.of(Env.sessionRoot)) {

    val id: String = UUID.randomUUID().toString().take(8)
    val startedAt: Instant = Instant.now()

    private val stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
        .withZone(ZoneId.systemDefault())
        .format(startedAt)

    val directory: Path = root.resolve("$stamp-$id")
    val cryptoTrace: Path = directory.resolve("crypto-trace.jsonl")
    val networkTrace: Path = directory.resolve("network-trace.jsonl")
    private val metadata: Path = directory.resolve("session.json")

    private val writer = Json { encodeDefaults = true; explicitNulls = false }
    private val lock = Any()

    @Volatile private var cryptoCount = 0L
    @Volatile private var networkCount = 0L

    /** Set when the directory cannot be created, so a read-only filesystem degrades quietly. */
    @Volatile private var disabled = false

    init {
        runCatching {
            Files.createDirectories(directory)
            Files.writeString(
                metadata,
                writer.encodeToString(
                    SessionInfo.serializer(),
                    SessionInfo(
                        id = id,
                        startedAt = startedAt.toString(),
                        directory = directory.toAbsolutePath().toString(),
                        cryptoTraceFile = cryptoTrace.toAbsolutePath().toString(),
                        networkTraceFile = networkTrace.toAbsolutePath().toString(),
                        cryptoEvents = 0,
                        networkEvents = 0,
                    ),
                ),
            )
        }.onFailure {
            disabled = true
            System.err.println("Session trace disabled: could not create ${directory.toAbsolutePath()} (${it.message})")
        }
    }

    fun appendCrypto(event: CryptoEvent) {
        if (append(cryptoTrace, writer.encodeToString(CryptoEvent.serializer(), event))) cryptoCount++
    }

    fun appendNetwork(event: TraceEvent) {
        if (append(networkTrace, writer.encodeToString(TraceEvent.serializer(), event))) networkCount++
    }

    private fun append(file: Path, line: String): Boolean {
        if (disabled) return false
        return synchronized(lock) {
            runCatching {
                Files.writeString(
                    file,
                    line + "\n",
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND,
                )
            }.isSuccess
        }
    }

    fun info(): SessionInfo = SessionInfo(
        id = id,
        startedAt = startedAt.toString(),
        directory = if (disabled) "(disabled)" else directory.toAbsolutePath().toString(),
        cryptoTraceFile = if (disabled) "(disabled)" else cryptoTrace.toAbsolutePath().toString(),
        networkTraceFile = if (disabled) "(disabled)" else networkTrace.toAbsolutePath().toString(),
        cryptoEvents = cryptoCount,
        networkEvents = networkCount,
    )

    /** Rewrites the metadata file with final counts. Called on shutdown. */
    fun seal() {
        if (disabled) return
        runCatching { Files.writeString(metadata, writer.encodeToString(SessionInfo.serializer(), info())) }
    }

    fun cryptoTraceText(): String =
        runCatching { Files.readString(cryptoTrace) }.getOrElse { "" }
}
