# Project handoff — state on 2026-10-09

Everything needed to resume this work on another machine: where each piece lives, what is
done, what the attest-key co-residency solution is, and what is still open.

## 1. Where things live

| What | Where |
|---|---|
| Testbed, both attacks, the linking-issuer countermeasure, the attest-key probe sources | this repo, `pennyw1ze/eudi-test` (**public**) |
| The paper (LaTeX + PDFs), its revision notes, the raw probe results from the phone, the Claude memory notes | `pennyw1ze/eudi-paper` (**private**), cloned into `docs/paper/` |

`docs/paper/` and `attestkey-probe/results/` are gitignored here on purpose: the paper is
unpublished, and the probe results contain the test phone's attestation certificates (device
identifiers). Never commit either to this repo.

### Branches (all pushed)

| Branch | Content |
|---|---|
| `main` | Base testbed: official EU reference issuer + verifier, the Kotlin wallet, console, crypto trace. |
| `attack-credential-pooling` | **Attack A** (presentation-time pooling): several wallet units, distinct PIDs per Keycloak subject, the degree (Learning Credential) as an EAA, combined presentations (DCQL `credential_sets`), batch issuance, and `POST /present/pooled`. Transcript: `docs/attack-a-pooling-transcript.md`, generator `scripts/attack-a-transcript.py`. |
| `attack-credential-transfer` | **Attack B** (issuance-time transfer), forked from `fb8ad30`: `IssuanceRequest.bindToWalletUnitId` makes the issuer bind Bob's credential to Alice's device key. Transcript: `docs/attack-b-transfer-transcript.md`. |
| `linking-issuer` | **The countermeasure** (forked from `attack-credential-pooling` at `4995c11`): linking issuer + verifier extension, now with the attest-key co-residency check (section 3). **This is the branch to continue on.** |

## 2. Setting up on a new machine

```bash
git clone git@github.com:pennyw1ze/eudi-test.git
cd eudi-test
git checkout linking-issuer
git clone git@github.com:pennyw1ze/eudi-paper.git docs/paper        # private

# optional: the real-device case of LinkingIssuerTest needs the phone's chains
mkdir -p attestkey-probe/results
cp docs/paper/private/attestkey-probe-results/*.json attestkey-probe/results/

make doctor && make setup && make up     # docker stack: issuer, verifier, gateway
make testbed                             # wallet + console on http://localhost:4000 (foreground)
cd wallet-core && ./gradlew test         # LinkingIssuerTest: 6/6 (real-device case skips without the results)
```

Claude Code memory does not travel with the repo. To restore it, copy
`docs/paper/private/claude-memory/*.md` into `~/.claude/projects/<slug>/memory/`, where
`<slug>` is the absolute path of the clone with every `/` replaced by `-` (on the old machine:
`-home-pennyw1ze-Desktop-Projects-eudi-test`).

Testbed facts that are easy to forget:
- Credential configuration ids: PID `eu.europa.ec.eudi.pid_vc_sd_jwt`; degree
  `urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt-compact`.
- Keycloak subjects `tneal`, `abianchi`, `jkowalski`, all with password `password`. New
  subjects need `docker compose --profile issuer up -d --force-recreate keycloak`.
- A code change needs `make testbed` restarted. The first `/issue` after a restart can return
  HTTP 500 while the issuer warms up; retry.

## 3. The countermeasure and the attest-key solution (branch `linking-issuer`)

### Roles and flow
- `LinkingIssuer` is a dedicated linking authority (the paper's instantiation 3): its own P-256
  key and self-signed certificate, which the verifier trusts. It keeps the reference issuer and
  verifier unmodified.
- `LinkingVerifier` adds the paper's verifier steps 3 and 4: verify the linking issuer's
  signature, then check that the link credential covers exactly the `cnf` keys of the presented
  credentials (as a set, because one device key can bind several credentials).
- `POST /present/linked` runs a normal OpenID4VP exchange (pooled resolver, so it also works
  across units), then `computeLink()` asks the linking issuer for a link and runs the verifier
  extension. Overall verdict = reference verifier accepted **and** link accepted.
- Console: "Present with link credential (countermeasure)". One unit = genuine holder; two or
  more = pooling test.
- Batch path: `Store` tracks used copies; `matchAcrossUnitsLinked` picks an unused copy and
  marks it spent, so consecutive presentations use different key pairs.

### Why the first design was replaced
The first version (committed in `e528f5b`) had each unit sign, under its WUA key, a
co-residency statement carrying a proof of possession per key over the presentation nonce.
That is **unsound**: a proof of possession is not co-residency. In Attack A Bob is online and
signs the relayed nonce anyway, so Alice can bundle Bob's key and Bob's proof under her own
WUA (or a self-minted one) and get a link. `attestkey-probe/legacy-pop-bypass/PoolingBypassTest.kt`
demonstrates the bypass: it passed 4/4 against `e528f5b` and is kept as evidence (it does not
compile against the current code).

### The attest-key design (2026-10-09)
The evidence is the WSCD's own key attestation, modelled on Android KeyMint with an
application **attest key** (`PURPOSE_ATTEST_KEY`, `setAttestKeyAlias`):

- `Attestation.kt`
  - `KeyDescription`: the part of Android's attestation extension
    (OID `1.3.6.1.4.1.11129.2.1.17`) the check reads: security level, challenge,
    hardware-enforced purposes, origin. It parses real device certificates too.
  - `AttestationAuthority`: emulated attestation PKI, a root plus one batch key shared by every
    emulated WSCD (as a factory batch key is shared by at least 100,000 devices).
  - `EmulatedWscd`: one per wallet unit. It generates an attest key certified by the batch key,
    then certifies every device key it generates (including batch copies) with that attest key,
    origin GENERATED. The attest key signs nothing else.
- `Keys.kt`: device keys are generated in the unit's `EmulatedWscd`;
  `attestationChain(key)` returns key cert → attest-key cert → batch cert → root.
- `LinkingIssuer.issueLink(chains)` accepts a key only if:
  1. the chain verifies up to a trusted root (a self-made "attest key" is worthless);
  2. the certifying key's attestation says purposes == `{ATTEST_KEY (7)}` and origin
     GENERATED. **This check is mandatory**: an ordinary WSCD key signs whatever it is given and
     could certify Bob's key; Android uses one subject name for every key, so only the purpose
     distinguishes an attest key;
  3. the leaf's origin is GENERATED (an imported key existed outside the WSCD);
  4. leaf and attest key have the same security level.

  It then groups keys by attest key (SHA-256 of its SPKI) and issues the link only if **one**
  attest key covers all of them. Link credential: ES256 JWS, `typ link-credential+jwt`,
  `vct urn:eudi:link:1`, single-use `jti`, 5-minute `exp`, `linked_keys`,
  `linked_key_thumbprints`. `LinkResult.distinctAttestKeys` reports the count. There is no
  challenge any more: a chain states a fact fixed at key generation, and freshness comes from
  the key-binding JWTs.
- Soundness argument: an attest key attests only keys generated in its own WSCD, so a pooled
  pair always arrives under two attest keys and is refused.
- Privacy cost: the attest key is a stable per-WSCD value, so whoever runs the linking issuer can
  recognise a wallet across requests. This argues for giving the role to the Wallet Provider,
  which already knows the device.

### Verification
- `wallet-core/src/test/kotlin/dev/eudi/testbed/LinkingIssuerTest.kt`, 6/6 passing:
  genuine keys linked and accepted; pooling refused (2 attest keys); forgery with an ordinary key
  refused by the purpose check; a WSCD outside the trusted PKI refused; a key without a chain
  refused; real-device chains from the phone (co-resident keys linked, forgery and cross-WSCD
  pairs refused).
- End to end: `scripts/linking-issuer-transcript.py` (needs `make up` + `make testbed`)
  regenerates `docs/linking-issuer-transcript.md`: genuine holder accepted, Attack A still
  accepted by the unmodified verifier, the same pool rejected with the link check, batch
  rotation, pooled batch rejected.

### On-device evidence (`attestkey-probe/`)
A Gradle-free Android app (`build.sh`: aapt2, javac, d8, apksigner; `PACKAGE=` builds a
second copy) plus host verifiers (`verify_attestkey.py`, `verify_foreign.py`) and drivers
(`run.sh`, `foreign.sh`). Run on a Samsung Galaxy S24 Ultra (SM-S928B), Android 16,
KeyMint 300, StrongBox and TEE, feature `app_attest_key`. All checks passed:
- The attest-key chain ends at a Google attestation root; keys signed by the attest key have
  origin GENERATED and the same security level.
- The attest key refuses arbitrary signing (`INCOMPATIBLE_PURPOSE`). Using a StrongBox attest
  key for a TEE key (or the reverse) is refused, by the Android framework.
- Forgery (Alice's ordinary signing key re-certifying Bob's key, with a genuine chain) is
  ACCEPTED without the purpose check and REJECTED with it.
- The attest key persists across runs, so a key generated today (PID) and one generated later
  (EAA) can be linked.
- Median keygen + attestation: about 60–90 ms (StrongBox and TEE).
- Foreign-key test (two apps standing in for Bob and Alice): Bob's StrongBox key is not
  exportable; Alice's attest key will not sign a certificate for Bob's key; key generation under
  an attest key only attests the new key; importing a key gives origin IMPORTED and no
  attestation setters exist for imports. No certificate Alice can obtain carries Bob's key under
  her attest key, even with both keys in the same physical StrongBox.
- Identifiers: ordinary keys' certificates carry none, but the attest key's issuer certificate
  does (StrongBox: a factory certificate shared across keys, runs and apps; TEE: a remotely
  provisioned certificate per app, valid about two weeks). Chains should therefore be seen only
  by the Wallet Provider.

### Open items
- Real-device policy checks not modelled: RootOfTrust (verified boot, locked bootloader),
  the attestation revocation status list (needed for soundness: with a leaked batch key anyone
  can mint a fake attest-key certificate), the `attestationApplicationId` check.
- A literal two-phone relay test.
- The link is issued on demand per presentation. With the nonce gone it could be pre-issued at
  issuance time (the paper's Phase 3).
- Not implemented: the k > 2 SD-JWT link credential with selectively disclosable keys and decoys.

## 4. The paper

The paper is being rewritten section by section. Its source, the revision status, the
fact-check notes and the draft rewrites are in the private repo (`docs/paper/revision/`).
Start from `docs/paper/revision/STATUS.md`.
