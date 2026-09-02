# EUDI Wallet Testbed

A local, self-contained environment for exercising and **tracking** the three roles of the
EUropean Digital Identity (EUDI) Wallet ecosystem — **Issuer**, **Wallet (holder)** and
**Verifier** — end to end on one machine.

Every protocol participant here is the official EU reference implementation. Nothing is
reimplemented or forked; this repository is the harness around them: a shared gateway, a
software wallet built on the official wallet libraries, and a console that records what
actually happened on the wire.

## What you get

| Role | Implementation | Runs as |
|---|---|---|
| Credential Issuer (OpenID4VCI) | [`eudi-srv-pid-issuer`](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer) | container |
| Authorisation Server | Keycloak + the upstream `pid-issuer-realm` | container |
| Revocation / status lists | [`eudi-srv-statuslist-py`](https://github.com/eu-digital-identity-wallet/eudi-srv-statuslist-py) | container |
| Verifier (OpenID4VP) | [`eudi-srv-web-verifier-endpoint-23220-4-kt`](https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt) | container |
| Verifier web UI | [`eudi-web-verifier`](https://github.com/eu-digital-identity-wallet/eudi-web-verifier) | container |
| **Wallet (holder)** | [`eudi-lib-jvm-openid4vci-kt`](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt), [`eudi-lib-jvm-openid4vp-kt`](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt), [`eudi-lib-jvm-sdjwt-kt`](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-sdjwt-kt) | host process |
| Console + tracing | this repository | same host process |

The wallet is a real software holder driving the official libraries, not a mock. It runs on
the host rather than in a container for one concrete reason: the issuer publishes its
metadata under `https://localhost/...`, and inside a container `localhost` would resolve to
the container itself rather than to the gateway.

## Architecture

```
                     ┌──────────────────────────────────────────┐
   browser ────────▶ │  testbed  :4000   console UI + wallet    │
                     │  OpenID4VCI / OpenID4VP client           │
                     │  protocol log · credential inspector     │
                     └───────────────────┬──────────────────────┘
                                         │  every request recorded
                                         ▼
                     ┌──────────────────────────────────────────┐
                     │  gateway (haproxy)  https://localhost     │
                     └───┬──────────┬──────────┬─────────────┬──┘
                         │          │          │             │
                  /pid-issuer     /idp   /token_status_list  /verifier
                         │          │          │             │
                   pid-issuer   keycloak  status-list   verifier-endpoint
                         │                                   │
                     postgres                            verifier-ui
```

Everything shares a single origin, `https://localhost`. That is what allows the wallet to
follow the URLs it discovers in issuer and verifier metadata verbatim, exactly as a real
wallet would.

## Requirements

- Docker with the daemon running, and your user in the `docker` group
- JDK 17 or newer (21 recommended)
- ~3 GB of free RAM (three JVMs plus Postgres)

Run `make doctor` to have all of this checked for you.

## Quick start

```bash
make doctor     # verify the host is ready
make setup      # clone the upstream repos into ./vendor, generate the gateway certificate
make up         # start issuer + verifier + gateway
make testbed    # run the wallet and console on http://localhost:4000
```

Then open <http://localhost:4000> and press **Issue to wallet**, followed by
**Present selected credential**.

To check the whole loop non-interactively, with the stack and the testbed both running:

```bash
make smoke
```

If memory is tight, bring the two sides up separately with `make up-issuer` and
`make up-verifier`.

## What "tracking" means here

**Protocol log.** Every HTTP exchange the wallet makes is recorded, with full request and
response headers and bodies, colour-coded by participant and grouped into flows. The
recording sits in an OkHttp interceptor rather than in the EUDI libraries, so what you see
is the traffic as it actually went out, not a re-narration of it.

**Credential inspector.** Issued credentials are decoded rather than shown as opaque
blobs: SD-JWT VC issuer JWTs with each disclosure unpacked into its salt / claim / value,
and `mso_mdoc` credentials decoded from CBOR — including the tag-24 wrapped
`IssuerSignedItem`s that would otherwise read as base64 noise.

## Layout

```
docker-compose.yml   the official images and build contexts, wired to one origin
config/              issuer configuration, lifted verbatim from upstream
gateway/             haproxy config and the generated TLS certificate
scripts/             doctor.sh (host check), smoke.sh (end-to-end check)
vendor/              upstream repositories, cloned by `make vendor`, never patched
wallet-core/         the software wallet, the tracer, and the console UI
```

`vendor/` is git-ignored. The testbed consumes upstream's published images and their
config assets; it does not carry a copy of their source.

## Notes and current limits

- **Issuance requires a login.** The reference `pid-issuer` implements only the
  authorization code grant, so every issuance involves a user authenticating at Keycloak.
  The console does this headlessly with the sample realm user (`tneal`), which is the only
  screen-scraping in the project; **Issue via browser login** performs the real redirect
  instead.
- **Presentation covers SD-JWT VC only.** Presenting an `mso_mdoc` credential requires
  assembling a signed `DeviceResponse` over a session transcript, which is not implemented;
  such a request is reported as unsupported rather than silently skipped. `mso_mdoc`
  credentials can still be issued, stored and inspected.
- **The wallet attests its own keys.** OpenID4VCI 1.0 requires a `key_attestation` in the
  JWT proof, which a real wallet receives from its wallet provider. The testbed mints and
  self-signs one.
- **TLS is not verified.** The gateway uses a certificate it generated itself, and the
  wallet is configured to accept it. This is a throwaway local harness; none of its
  security settings are meant to travel.

## Sources

- <https://github.com/eu-digital-identity-wallet>
- <https://playground.eudi-wallet.dev/>
- <https://issuer-backend.eudiw.dev/issuer/credentialsOffer/generate>
- <https://verifier-backend.eudiw.dev/swagger-ui>
