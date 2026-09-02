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

Docker, JDK 17+ (21 recommended), ~3 GB free RAM. Run `make doctor` to check.

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

The console drives one credential through its whole life. The **Protocol log** at the
bottom records every HTTP exchange as you go — expand any row to see headers and bodies.

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

Narrow the query to a single claim and present again — the inspector and log show only
that claim being disclosed. That is selective disclosure working.

---

## Known issues

- **Issuance fails at client authentication.** Keycloak rejects the testbed's client
  attestation at the PAR endpoint with `"Authentication failed."` The reference issuer
  accepts only attestation-based client authentication, and the testbed's self-signed
  wallet-provider attestation is not yet accepted. Until this is resolved the wallet
  cannot hold a credential, so steps 2 and 3 cannot complete. The Verifier tab can still
  open transactions, and the Issuer tab shows the live issuer metadata.
- **Presentation covers SD-JWT VC only.** Presenting an `mso_mdoc` needs a signed
  `DeviceResponse` over a session transcript, which is not implemented. Such a request is
  reported as unsupported. mdocs can still be issued, stored and inspected.
- **TLS is not verified.** The gateway uses a self-signed certificate and the wallet is
  configured to accept it. Local harness only.

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
wallet-core/         the wallet, the tracer and the console UI
```

## Sources

- <https://github.com/eu-digital-identity-wallet>
- <https://playground.eudi-wallet.dev/>
- <https://verifier-backend.eudiw.dev/swagger-ui>
