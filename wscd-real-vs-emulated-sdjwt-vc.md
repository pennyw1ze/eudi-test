# WSCD (Secure Element) in the EUDI Wallet: Real Hardware vs. the Testbed Emulation

This document lists the cryptographic assets, data objects, and operations that originate
from or reside inside the **Secure Element** (Wallet Secure Cryptographic Device — WSCD /
WSCA). For each one it states three things:

1. **Real WSCD** — what a certified hardware wallet does.
2. **Testbed** — what our software wallet actually does (with source references).
3. **Does the difference matter?** — in general, and for our pooling attack (**Attack A**,
   presentation-time relay pooling) in particular.

### Scope

Our attack is **demonstrated** on the **SD-JWT VC** presentation flow, so the inline
analysis below is written against it. **ISO/IEC 18013-5 mdoc is equally in scope and equally
legitimate** — it is part of the official EU reference implementation, binds to the *same*
WSCD device key, and is governed by the same principle (device-local assurance is never
conveyed to the verifier); only the presentation *encoding* differs (an mdoc `DeviceAuth`
signature over a session transcript instead of a KB-JWT). See the mdoc note after the
matrix.

Genuinely out of scope — because they belong to a *different cryptographic wallet
implementation* rather than the SD-JWT VC / mdoc baseline — are BBS# / anonymous-credential
schemes, ZKP privacy variants (Longfellow, Rufini, Vision), Qualified Electronic Signatures,
WebAuthn pseudonyms, and non-P-256 algorithms. They are collected in
[§4](#4-out-of-scope-different-cryptographic-implementations) rather than analysed inline.

> **Principle:** anything produced by the official EU reference implementation (the issuer,
> the verifier, and the `eudi-lib-*` libraries) is treated as legitimate and authoritative.
> The only things this document flags as emulated or faked are artifacts our *own* testbed
> wallet shim mints (self-signed KA/WUA, software keys) — never the behaviour of the upstream
> components.

### The thesis in one paragraph

Everything the WSCD adds falls into one of two buckets: **(a) issuance-time trust
anchoring** (Key Attestation, Wallet Unit Attestation), or **(b) device-local assurance**
(non-extractable keys, hardware-gated user authentication, security-posture reporting).
Bucket (b) is **never conveyed to or verified by the verifier during a presentation**
(SD-JWT VC or mdoc alike) — the verifier only sees a public key in `cnf` and a per-session
signature (KB-JWT, or mdoc `DeviceAuth`) that verifies against it, which is byte-for-byte
identical whether it was produced in StrongBox or in JVM heap. Bucket (a) is protocol-visible,
but only at *issuance*, and Attack A
operates at *presentation* with two holders who were each legitimately provisioned. That is
why the emulation is faithful enough for the attack, and why real hardware would not stop
it.

Verdict legend: ✅ **emulated** (real behaviour runs and is exchanged on the wire) ·
⚠️ **asserted-only** (a claim is placed on the wire but nothing performs the work) ·
❌ **ignored** (absent from the implementation).

---

## 1. Primary Cryptographic Key Material

### 1.1 Device Private Key ($dsk$ / $sk_d$)

* **Real WSCD**: Generated inside the WSCD (StrongBox / Secure Enclave / eSE / smart card);
  stored in tamper-resistant memory and **never leaves the hardware boundary**. Used for
  Proof of Possession / device binding during presentation.
* **Testbed** — ✅ *emulated (software)*: Each wallet unit generates its own P-256 key
  (`ECKeyGenerator(Curve.P_256)`) and uses it to sign the presentation key-binding JWT
  (`Keys.kt:78`, `Presentation.kt:326`). It is a genuine, per-unit signing key — but it
  lives in JVM heap, is extractable, and can be copied and used from anywhere, which no
  counterparty can detect (`Keys.kt:113`).
* **Does the difference matter?**
  * *In general:* No runtime protocol step proves non-extractability to a counterparty. The
    only assertion of it is the Key Attestation (see 2.1), which is trust-anchored at
    issuance, not re-checked at presentation.
  * *For Attack A:* **No.** The attack never extracts, clones, or shares a private key. Each
    colluder signs with its **own** legitimate device key. Making the key non-extractable
    changes nothing, because the colluders never need to move a key between devices.

### 1.2 Device Public Key ($dpk$ / $PK_u$)

* **Real WSCD**: Exported at key generation; embedded by the issuer inside the PID/EAA
  (`cnf`), and used by verifiers to check the PoP signature at presentation.
* **Testbed** — ✅ *emulated*: The device public key is placed in the credential's `cnf.jwk`
  at issuance and in the Key Attestation's `attested_keys`, and the verifier checks the
  KB-JWT against it (`Crypto.kt:12`, `Presentation.kt:328`).
* **Does the difference matter?**
  * *In general:* The public key on the wire is identical in form (a P-256 JWK) regardless
    of where the private half lives. Provenance is the only difference, and provenance is
    carried by the Key Attestation, not by the key itself.
  * *For Attack A:* **No.** The verifier binds each credential to its own `dpk`; the attack
    presents two credentials, each bound to a *different, genuine* `dpk`. Real hardware
    produces the same two distinct public keys.

---

## 2. Hardware Attestations and Certificates

### 2.1 Key Attestation (KA)

* **Real WSCD**: An X.509 chain rooted at the device manufacturer / platform vendor CA
  (Google, Apple, Samsung Knox, NXP/Infineon…), proving to the Wallet Provider and to
  PID/EAA issuers that a given `dpk` was generated in certified hardware at eIDAS LoA High
  (CC EAL4+/AVA_VAN.5), that the key is non-exportable, and that use requires
  hardware-enforced user authentication.
* **Testbed** — ✅ *emulated + checked (trust anchor faked)*: A real signed
  `key-attestation+jwt` is minted, attached to the JWT proof of the credential request, and
  the issuer enforces its structure and status: it carries `iat`, `exp`, `attested_keys`,
  `key_storage`, `user_authentication`, `certification`, and a dereferenceable
  `key_storage_status`, and dropping any one makes the issuer reject it; the issuer demands
  `iso_18045_high` and refuses a lower level (`Keys.kt:148`). What is faked: the chain is
  **self-signed**, not manufacturer-rooted, and the issuer accepts it only because its
  wallet-provider **trust validator is switched off** ("Trusting all Wallet Providers",
  `Keys.kt:90`).
* **Does the difference matter?**
  * *In general:* **This is the one place the gap is protocol-visible.** A production issuer
    with trust validation enabled would reject our self-signed KA. So KA is the real
    boundary between "emulated" and "certified" — but it lives entirely at **issuance**.
  * *For Attack A:* **No.** Both colluders can each legitimately obtain a valid,
    hardware-rooted KA for their own device from a real provider. The attack takes place at
    presentation, where the KA is not presented or checked at all.

### 2.2 Wallet Unit Attestation (WUA)

* **Real WSCD**: A Wallet-Provider-signed statement binding one or more `dpk` values to a
  specific certified WSCD instance (co-residence), letting issuers confirm the target device
  is genuine and not revoked before issuing.
* **Testbed** — ✅ *emulated + checked (trust anchor faked)*: Realised as OAuth2
  attestation-based client authentication. A signed `oauth-client-attestation+jwt` with a
  `cnf` key, wallet metadata, and a `client_status` reference is sent on every token
  request; the issuer's ABCA extension validates it, and **both** the `client_status` and
  the KA's `key_storage_status` revocation lists are dereferenced and enforced
  (`WalletProvider.kt:56`, `KeyAttestation.kt`). Faked: self-signed, accepted only because
  the realm's `eudiw-abca` client has an empty `trustValidator.serviceUrl`
  (`WalletProvider.kt:29`). Co-residence of *multiple* keys is not exercised —
  `attested_keys` holds exactly one key.
* **Does the difference matter?**
  * *In general:* Same as KA — trust anchoring at issuance. Revocation *is* modelled and
    enforced, so the lifecycle check is real; only the root of trust is not.
  * *For Attack A:* **No.** Each colluder holds a valid, non-revoked WUA for its own unit.
    Nothing about a genuine WUA prevents two separately-attested units from cooperating.

---

## 3. Dynamic Operational Artifacts and Proofs

### 3.1 Proof of Possession (PoP) Signature ($\sigma_{PoP}$)

* **Real WSCD**: Computed inside the WSCD, per presentation, over a fresh verifier
  challenge, gated by hardware user authentication; proves the holder currently possesses
  the physical device bound to the credential.
* **Testbed** — ✅ *emulated (SD-JWT KB-JWT)*: Each presentation builds a fresh key-binding
  JWT over the verifier's `nonce` and `audience`, signed by the unit's device key, ephemeral
  per session (`Presentation.kt:322`).
* **Does the difference matter?**
  * *In general:* **No — and this is the crux.** The verifier only checks that the KB-JWT
    signature verifies against the credential's `cnf` public key. A software ECDSA signature
    and a StrongBox ECDSA signature over the same input are indistinguishable to the
    verifier; there is no "this was produced in an SE" signal on the wire.
  * *For Attack A:* **This is precisely the gap the attack exploits.** Two colluders produce
    two valid PoPs from two devices; each verifies against its own credential's `cnf`. Real
    hardware makes each PoP "more genuine" but does **not** give the verifier any way to tell
    that the two device keys belong to two *different people*. Hardware is not merely
    irrelevant here — the attack is a demonstration of the limit of what device-bound PoP can
    prove.

### 3.2 Hardware-Gated Multi-Factor Authentication (user presence)

* **Real WSCD**: Key use (signing a PoP, releasing a disclosure) requires local user
  authorization — biometric or PIN — with hardware throttling and lockout after failures.
* **Testbed** — ⚠️ *asserted-only*: The Key Attestation *claims*
  `user_authentication: iso_18045_high`, but **no user authentication happens at all**
  (`Keys.kt:163`, `Keys.kt:217`). There is no biometric, PIN, retry counter, or throttle.
* **Does the difference matter?**
  * *In general:* User authentication is local to the device and is **never proven to the
    verifier** in an SD-JWT VC presentation — there is no "user was present" attribute on the
    wire that the RP verifies. So whether it is emulated or merely asserted is invisible to
    counterparties.
  * *For Attack A:* **No.** Even with real per-use biometric gating, each colluder authorizes
    their *own* device willingly. Hardware MFA defends against a thief or a coerced release —
    not against two consenting holders who each authenticate normally. It cannot, by
    construction, prevent pooling.

### 3.3 Hardware Metadata & Security Posture Flags

* **Real WSCD**: Reports $WSCD_{id}$, chip family, patch level, StrongBox-vs-TEE flags, and
  root/compromise status to the Wallet Provider, enabling detection of rooted or unpatched
  devices and WUA revocation.
* **Testbed** — ❌ *ignored*: No posture is reported. The only storage descriptor is an
  honest self-label, `"software (JVM heap)"` (`Keys.kt:134`); there is no compromise
  detection or posture-driven revocation.
* **Does the difference matter?**
  * *In general:* Posture is a Wallet-Provider↔device concern at provisioning; it never
    appears in an SD-JWT VC presentation, so the verifier's decision does not depend on it.
  * *For Attack A:* **No.** The colluders' devices are honest and uncompromised — they are
    simply used cooperatively. Posture monitoring has nothing anomalous to detect.

---

### A note on ISO mdoc

mdoc is **not** excluded. It is a first-class, official EU credential format and binds to the
same WSCD device key analysed above. The difference from SD-JWT VC is purely the presentation
encoding: an mdoc presentation is a signed `DeviceResponse` whose `DeviceAuth` signs a
session transcript, where SD-JWT VC uses a KB-JWT over `nonce`/`audience`. Every row of the
matrix applies unchanged — the device key (1.1/1.2), KA (2.1), WUA (2.2), the per-session PoP
(3.1, now `DeviceAuth`), user authentication (3.2), and posture (3.3) are the same WSCD
elements. The testbed currently *demonstrates* the pooling attack over SD-JWT VC because its
presentation path builds KB-JWTs and does not yet build a `DeviceResponse`
(`Presentation.kt:60`); that is an implementation choice in our shim, not a WSCD gap and not
a limitation of the official mdoc stack, which we treat as legitimate.

## 4. Out of scope (different cryptographic implementations)

These elements belong to a *different wallet cryptographic implementation*, not the
SD-JWT VC / mdoc baseline the attack targets. They are deliberately excluded.

| Element | Why out of scope | Testbed status |
| :--- | :--- | :--- |
| **Blind / split signatures (BBS#)** | Different wallet cryptographic implementation | ❌ ignored |
| **`dpk` hashing / commitment / ZKP** (Longfellow, Rufini, Vision) | Privacy-preserving variants, not the baseline | ❌ ignored |
| **QES / QSCD keys** | Separate wallet function (qualified signatures), not credential presentation | ❌ ignored |
| **WebAuthn / passkey pseudonym keys** | Separate wallet function (pseudonymous auth) | ❌ ignored |
| **RSA / ECSchnorr device keys** | The SD-JWT VC / mdoc flow here is ES256/P-256 only | ❌ ignored |
| **Transactional-data signing (PSD2/SCA)** | Payment authorization flow, not credential presentation | ❌ ignored |

---

## 5. Summary matrix (in-scope: SD-JWT VC and mdoc)

| SE element | Testbed status | Real vs emulated: the one real difference | Matters for Attack A? |
| :--- | :--- | :--- | :--- |
| Device private key (1.1) | ✅ emulated (software) | Non-extractable SE key vs extractable heap key | No — colluders use their own keys, never share one |
| Device public key (1.2) | ✅ emulated | None on the wire; identical P-256 JWK | No — two credentials, two genuine `dpk`s either way |
| Key Attestation (2.1) | ✅ emulated + checked | Manufacturer-rooted chain vs self-signed; trust validator on vs off | No — issuance-time; both colluders legitimately hold one |
| Wallet Unit Attestation (2.2) | ✅ emulated + checked | Trusted root vs self-signed (revocation is real) | No — each unit has a valid, non-revoked WUA |
| PoP / KB-JWT (3.1) | ✅ emulated | Signature computed in SE vs in software — **indistinguishable to the verifier** | **This is the exploited gap** — hardware cannot prove two keys = one person |
| User authentication (3.2) | ⚠️ asserted-only | Real biometric/PIN gate vs none — never proven to the verifier anyway | No — colluders each authenticate their own device willingly |
| Hardware posture (3.3) | ❌ ignored | Posture reporting + compromise detection vs none | No — honest, uncompromised devices, cooperatively used |

**Bottom line:** for the SD-JWT VC presentation flow, the only real-vs-emulated difference
that is protocol-visible is the **trust anchoring of the Key Attestation and Wallet Unit
Attestation at issuance** (2.1, 2.2). Every device-local property — non-extractability, user
authentication, posture — is invisible to the verifier at presentation time. Attack A takes
place at presentation, between two holders who were each legitimately provisioned with
genuine hardware; therefore none of these WSCD properties, real or emulated, prevents the
attack.
