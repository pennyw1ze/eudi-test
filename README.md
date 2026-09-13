# EUDI Wallet Testbed

A local environment for exercising and tracking the three roles of the EUropean Digital
Identity (EUDI) Wallet ecosystem — **Issuer**, **Wallet**, **Verifier** — from one web
console at `http://localhost:4000`.

Every protocol participant is the official EU reference implementation. This repository
is the harness around them: a shared gateway, a software wallet built on the official
wallet libraries, and a console that records what happened on the wire.

| Role | Implementation | Runs as |
|---|---|---|
| Issuer (OpenID4VCI) | [`eudi-srv-pid-issuer`](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer) | container |
| Authorisation server | Keycloak + upstream `pid-issuer-realm` | container |
| Revocation | [`eudi-srv-statuslist-py`](https://github.com/eu-digital-identity-wallet/eudi-srv-statuslist-py) | container |
| Verifier (OpenID4VP) | [`eudi-srv-web-verifier-endpoint-23220-4-kt`](https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt) | container |
| Wallet (holder) | [`openid4vci-kt`](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt), [`openid4vp-kt`](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt), [`sdjwt-kt`](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-sdjwt-kt) | host process |
| Console + tracing | this repository | same host process |

Everything is published under one origin, `https://localhost`, so the wallet can follow
the URLs it discovers in metadata verbatim — as a real wallet would.

## Requirements

Docker, Docker Compose v2 (the `docker compose` plugin), JDK 17+ (21 recommended), ~3 GB
free RAM. Run `make doctor` to check.

## Start

```bash
make doctor     # check the host
make setup      # clone upstream repos, fetch sources, generate the gateway certificate
make up         # start issuer + verifier + gateway (asks for sudo if needed)
make testbed    # run the wallet + console — stays in the foreground
```

Open <http://localhost:4000>. The sidebar switches between the three roles and shows
which services are reachable.

---

# Guide

The console drives one credential through its whole life. The **Cryptographic trace** at
the bottom records every proof, signature and disclosure as you go.

## 0. Participants

The sidebar lists the three kinds of participant, each with a **+** button.

- **Wallet units** — a unit is one holder: its own device, DPoP, client-PoP and
  attestation keys, and its own credential store. Adding one generates fresh key
  material. Because a credential is bound to a device key through `cnf`, a credential
  issued to one unit cannot be presented by another; running two side by side is the
  cheapest way to watch that binding hold.
- **Issuers** — a credential issuer identifier plus the client id and login the wallet
  should use against it.
- **Verifiers** — a Verifier API base plus the intended use to present under.

Issuers and verifiers persist to `runs/participants.json` so a restart keeps them.
Wallet units do not: they are key material, and resurrecting yesterday's keys would
quietly undo the fresh session each trace file records.

## 1. Issue a credential

The wallet asks the issuer for a credential; the issuer authenticates the user, then
signs and returns it. This is a single step in the UI — the signing happens issuer-side.

**Wallet** tab → pick a **credential configuration** → **Issue to wallet**.

- `eu.europa.ec.eudi.pid_vc_sd_jwt` — a PID as an SD-JWT VC (the one that can be presented)
- `eu.europa.ec.eudi.pid_mso_mdoc` — a PID as an ISO mdoc
- `org.iso.18013.5.1.mDL` — a mobile driving licence
- `..._deferred` variants park on the deferred endpoint and are not supported

**Issue to wallet** logs in headlessly as the sample realm user (`tneal`).
**Via browser login** opens the real Keycloak login instead.

Behind that button the wallet performs the full OpenID4VCI exchange: resolve issuer
metadata, authenticate the client with a wallet-provider attestation, obtain a
DPoP-bound access token, then request the credential with a JWT proof carrying a key
attestation. The issuer signs the credential and the wallet stores it.

## 2. Inspect what was signed

Click the credential under **Held credentials**. The inspector decodes it rather than
showing a blob:

- **SD-JWT VC** — issuer-signed JWT header and payload, plus every disclosure unpacked
  into its salt, claim name and value
- **mdoc** — CBOR decoded, including the tag-24 wrapped `IssuerSignedItem`s

This is where you confirm the issuer's signature and see exactly which claims it asserted.

## 3. Verify it

**Verifier** tab. The console acts as the relying party here.

Edit the **DCQL query** to say which claims you want — the default asks for
`family_name` and `given_name` from a PID. Then:

- **Request & present** runs the whole loop: the verifier opens a transaction, the wallet
  resolves the request, selects only the requested disclosures, signs a key-binding JWT
  and posts the `vp_token`, and the verifier's verdict is read back.
- **Open transaction only** stops after the request and shows the
  `authorizationRequestUri`, so a real phone wallet can pick it up instead.

Narrow the query to a single claim and present again — the trace shows only that claim
being released and counts the rest as withheld digests. That is selective disclosure
working.

## 4. Read the cryptographic trace

The panel at the bottom has two tabs. **Network** is the raw HTTP evidence. **Cryptographic
trace** is the one to read: it answers who proved what to whom, over which key, bound to
which values — the layer the protocol actually rests on.

Each row carries an operation (`keygen`, `sign`, `verify`, `disclose`, `bind`), the party
that performed it, the artefact under its specification name, and the keys involved as
coloured thumbprint chips. **The same colour is the same key.** That is what makes the
binding chain checkable by eye: follow one colour and you see the device key generated,
attested by the wallet provider, proven to the issuer, written into the credential's
`cnf.jwk`, and finally signing the key binding JWT. Expand a row for what the artefact
commits to, its JOSE header and payload.

Rows whose claim outruns the testbed's real assurance carry a **testbed caveat** saying so
— the key attestation asserting `iso_18045_high` over a key in JVM heap is the one that
matters. See the LoA note under Known issues.

Most events are recovered from the wire, so they record what the counterparty actually
received. Two exchanges are exceptions: key generation never leaves the process, and the
reference issuer encrypts both the credential request and the credential response
(`ECDH-ES` + `A128GCM`). Those arrive as `Encrypted request/response (JWE)` rows, and the
proof, key attestation and credential sealed inside them are recorded from within the
wallet so the trace has no silent gap where its most important step should be.

## 5. Keep the trace

Every run writes a fresh directory under `runs/`:

```
runs/<timestamp>-<id>/
  session.json         when the run started, where its files are, how many events
  crypto-trace.jsonl   one cryptographic event per line
  network-trace.jsonl  one HTTP exchange per line
```

JSON Lines, appended as events happen — a run that is killed still leaves everything it
observed, and the files are greppable without a parser. The sidebar shows the current
directory and links the crypto trace for download; `GET /api/session` reports the same.

---

## Known issues

- **A credential cannot be presented for the first 20 seconds after it is issued.** The
  reference issuer sets `nbf` to `iat + 20s`, so an immediate presentation is correctly
  rejected with `ContainsInvalidJwt: SD-JWT is not active yet`. Wait, then present, and
  the loop closes: verifier accepts the `vp_token`. This was previously recorded here as
  "presentation not confirmed end to end" and blamed on the attestation classification
  table — that table did need configuring (it is now, in `docker-compose.yml`), but the
  remaining failure was the validity window.
- **Presentation covers SD-JWT VC only.** Presenting an `mso_mdoc` needs a signed
  `DeviceResponse` over a session transcript, which is not implemented. Such a request is
  reported as unsupported. mdocs can still be issued, stored and inspected.
- **TLS is not verified.** The gateway uses a self-signed certificate and the wallet is
  configured to accept it. Local harness only.
- **The wallet attests its own keys.** OpenID4VCI requires a key attestation, and
  attestation-based client authentication requires another; a real wallet receives both
  from its wallet provider after device attestation. The testbed signs its own and
  asserts `iso_18045_high` while holding keys in JVM memory. Nothing in the protocol can
  detect this, which is what makes a software wallet possible at all — but the assertion
  is untrue, and none of it should travel beyond this harness. Every affected row in the
  cryptographic trace says so in its caveat; the honest way to read the trace is that it
  proves the protocol, not the assurance level.
- **Two upstream files needed fixing** to make any of this work, both patched in
  `config/status-list/`: the status list endpoint compared the `Accept` header with `==`,
  returning 406 to every real client, and its URIs pointed at `https://localhost`, which
  resolves to the container itself for the issuer and verifier.

## Commands

```
make doctor      check host prerequisites
make setup       vendor upstream sources + certificate
make up          start the stack        make down / make clean
make testbed     run wallet + console
make smoke       end-to-end check (needs both running)
make logs        tail the stack         make logs S=pid-issuer
make issuer-log  capture issuer.log + keycloak.log
make diag        container states + logs to diag.txt
```

## Layout

```
docker-compose.yml   official images and build contexts, wired to one origin
config/              issuer env, status list config and Dockerfile
gateway/             haproxy config + generated TLS certificate
scripts/             doctor.sh, smoke.sh
vendor/              upstream repositories (git-ignored, never patched)
runs/                per-run traces + participants.json (git-ignored)
wallet-core/         the wallet, the tracer and the console UI
```

Inside `wallet-core/src/main/kotlin/dev/eudi/testbed/`:

```
Registry.kt       wallet units, issuers and verifiers
Keys.kt           one unit's key material; mints the key attestation
Issuance.kt       OpenID4VCI in the holder role
Presentation.kt   OpenID4VP in the holder role
Verifier.kt       the relying party side, driven through the Verifier API
Crypto.kt         the cryptographic event model and its in-memory log
Jose.kt           JOSE and SD-JWT decoding, RFC 7638 thumbprints
CryptoScanner.kt  recovers the cryptographic layer from the exchanges on the wire
Trace.kt          the network log and the OkHttp interceptor that feeds both
Session.kt        the per-run trace directory
Inspect.kt        decodes a stored credential for the inspector
```

## Sources

- <https://github.com/eu-digital-identity-wallet>
- <https://playground.eudi-wallet.dev/>
- <https://verifier-backend.eudiw.dev/swagger-ui>
