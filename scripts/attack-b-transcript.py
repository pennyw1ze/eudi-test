#!/usr/bin/env python3
"""Run Attack B (issuance-time credential transfer) and emit an annotated transcript.

The attack, from Rufini & Visconti, "Hardware Binding Without Non-Transferability"
(No Pooling, No Party), Section 5.2: a holder causes an attribute attestation (EAA/QEAA)
to be issued BOUND TO A DIFFERENT DEVICE'S KEY than the one that authenticated. The
issuer never checks that the bound key is co-resident with the credential used to
authenticate the holder, so the credential ends up presentable by the attacker's device
ALONE, indefinitely, without the authenticating holder. Transfer, not delegation. The
paper shows (Section 5.3) this is a specification gap: ARF ISSU_05 mandates the delivery
co-residency check for the PID at LoA High but explicitly exempts QEAAs/EAAs.

Expects `make up` and a running testbed on :4000. Writes docs/attack-b-transfer-transcript.md.

    python3 scripts/attack-b-transcript.py
"""
import json
import os
import sys
import time
import urllib.request

API = os.environ.get("BASE", "http://localhost:4000") + "/api"
DEG_CFG = "urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt-compact"
OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "attack-b-transfer-transcript.md")

# One credential query for the university degree, asking the subject's name and the
# graduation date — the attributes that will, after the transfer, live on Alice's device
# while naming Bob.
DEG_DCQL = {
    "credentials": [
        {"id": "degree", "format": "dc+sd-jwt",
         "meta": {"vct_values": ["urn:eu.europa.ec.eudi:learning:credential:1"]},
         "claims": [{"path": ["family_name"]}, {"path": ["given_name"]},
                    {"path": ["date_of_issuance"]}]},
    ]
}


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read().decode())


def add_unit(label):
    return call("POST", "/wallet-units", {"label": label})["id"]


def short(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def timeline(flow_id):
    crypto = [("C", e) for e in call("GET", "/crypto?since=0") if e["flowId"] == flow_id]
    net = [("N", e) for e in call("GET", "/trace?since=0") if e["flowId"] == flow_id]
    rows = crypto + net
    rows.sort(key=lambda r: (r[1]["at"], 0 if r[0] == "N" else 1))
    lines = []
    for kind, e in rows:
        t = e["at"][11:19]
        if kind == "N":
            if e["kind"] == "http":
                d = f" ({e['durationMs']}ms)" if e.get("durationMs") is not None else ""
                lines.append(f"[{t}] HTTP  {e['actor']}: {e.get('method','')} "
                             f"{short(e.get('url',''), 56)} -> {e.get('status','')}{d}")
            elif e["kind"] == "step":
                lines.append(f"[{t}] STEP  {e['actor']}: {short(e.get('note',''), 108)}")
            elif e["kind"] == "error":
                lines.append(f"[{t}] ERROR {short(e.get('note',''), 108)}")
        else:
            lines.append(f"[{t}] {e['operation'].upper():8} {e['actor']}: {e['artifact']}")
            lines.append(f"           {short(e['summary'], 108)}")
            for k in e.get("keys", []):
                lines.append(f"           key[{k.get('role','?')}] {k.get('thumbprint','')[:22]}…")
            for bk, bv in (e.get("binds") or {}).items():
                lines.append(f"           . {bk}: {short(bv, 72)}")
            if e.get("caveat"):
                lines.append(f"           ! {short(e['caveat'], 150)}")
    return "\n".join(lines)


def main():
    bob = add_unit("Bob (authenticates as Anna Bianchi)")
    alice = add_unit("Alice (receives the transferred degree)")

    # Attack B: Bob runs the authorisation leg (authenticates as Anna Bianchi) but the
    # key-binding proof is signed by ALICE's device key, so the degree binds to Alice.
    for _ in range(3):
        iss = call("POST", "/issue", {
            "walletUnitId": bob, "bindToWalletUnitId": alice,
            "credentialConfigurationId": DEG_CFG,
            "username": "abianchi", "password": "password", "autoLogin": True,
        })
        if iss.get("status") == "issued":
            break
        time.sleep(3)
    if iss.get("status") != "issued":
        raise SystemExit("issuance failed: " + json.dumps(iss)[:300])

    alice_creds = call("GET", "/credentials?walletUnitId=" + alice)
    bob_creds = call("GET", "/credentials?walletUnitId=" + bob)

    # Alice presents the degree alone — Bob is not involved.
    pres = call("POST", "/present", {"walletUnitId": alice, "dcqlQuery": DEG_DCQL})
    # Bob cannot present it: he holds nothing.
    bob_pres = call("POST", "/present", {"walletUnitId": bob, "dcqlQuery": DEG_DCQL})

    fields = {
        "iss_flow": iss["flowId"], "iss_timeline": timeline(iss["flowId"]),
        "iss_bound_to": iss.get("walletUnitId", "?"),
        "alice_n": str(len(alice_creds)), "bob_n": str(len(bob_creds)),
        "pres_flow": pres["flowId"], "pres_timeline": timeline(pres["flowId"]),
        "pres_status": pres.get("status", "?"),
        "pres_result": json.dumps({k: pres.get(k) for k in
                                   ("status", "walletUnitId", "presentedCredentialId",
                                    "presentedCredentialIds", "requestedClaims")},
                                  indent=2, ensure_ascii=False),
        "bob_pres_status": bob_pres.get("status", "?"),
        "bob_pres_error": short(bob_pres.get("error", ""), 160),
    }
    doc = DOC_TEMPLATE
    for k, v in fields.items():
        doc = doc.replace("{" + k + "}", str(v))
    path = os.path.abspath(OUT)
    with open(path, "w") as f:
        f.write(doc)
    print("wrote", path)
    ok = (iss.get("status") == "issued" and iss.get("walletUnitId") == alice
          and len(alice_creds) == 1 and len(bob_creds) == 0
          and pres.get("status") == "presented" and bob_pres.get("status") != "presented")
    print("PASS" if ok else "FAIL",
          "| issued->alice:", iss.get("walletUnitId") == alice,
          "| alice holds:", len(alice_creds), "| bob holds:", len(bob_creds),
          "| alice presents:", pres.get("status"), "| bob presents:", bob_pres.get("status"))
    return 0 if ok else 1


DOC_TEMPLATE = r"""# Attack B — issuance-time credential transfer — annotated execution transcript

*Generated by `scripts/attack-b-transcript.py` against the running testbed. Regenerate
after any change to the issuance code so the transcript matches the current build.*

This is a faithful, run-time reproduction of **Attack B** from Rufini & Visconti,
*Hardware Binding Without Non-Transferability: Credential Pooling Attacks on the European
Digital Identity Wallet, and a Legacy-Compatible Defence* ("No Pooling, No Party"),
**Section 5.2**. It is exercised against the **official EUDI reference issuer**
(`eudi-srv-pid-issuer`), unmodified: the transfer is a single-line change in the *holder*,
not in the issuer.

---

## 1. What the attack is (as in the paper)

Device binding relates a credential key to a **device**; identity proofing relates a
**session** to a **person**. The Wallet Unit Attestation (WUA) assures the issuer that the
credential key is co-resident in a certified WSCD — but **nothing checks that the key being
bound is co-resident with the credential used to authenticate the holder** (paper §2.3,
§5.2). Attack B drives a wedge into exactly that gap:

> Where an Attestation Provider supports a decoupled or cross-device authorisation flow,
> Bob may authenticate — including by presenting his own PID — while the key submitted for
> binding is generated in Alice's WSCD. The issuer binds Bob's attributes to a key in
> Alice's device. Every subsequent check is honest: Alice's WUA correctly attests her
> WSCD, the key genuinely resides there and is non-exportable, and Bob's proofing genuinely
> occurred. The credential is thereafter presentable by Alice alone, indefinitely, without
> Bob's participation. This is transfer, not delegation. — paper §5.2

**Threat model** (paper §4.1): honest-but-colluding holders, each in sole control of their
own Wallet Unit; no key is ever extracted. What changes hands is not a key but a *binding*:
after one cooperative issuance, a correctly-signed, non-exportable credential naming Bob
lives in Alice's device and works without him.

### Why it is a specification gap, not a bug (paper §5.3)

The ARF contains precisely the check that would close Attack B, and scopes it out of the
credentials the attack targets:

- **ISSU_05** obliges a Wallet Unit to run a LoA-High activation process for a newly issued
  **PID**, whose stated purpose is *to verify that the PID was delivered into the Wallet
  Unit and WSCA/WSCD of the User who is the subject of the PID* — exactly the
  co-residency-with-identity property Attack B violates.
- The same note declares ISSU_05 **not applicable to QEAAs, PuB-EAAs, or non-qualified
  EAAs**, on the grounds that these are not identity means.
- The binding requirements that *do* apply to EAAs (WUA_09a, WUA_11a, WUA_12) are strictly
  **device-scoped**: bind to a key in the attested WUA, verify the attestation, prove
  possession. Every one holds in this attack, because the key genuinely is in a certified
  WSCD and the wallet genuinely possesses it. **What no requirement establishes is that the
  WSCD belongs to the subject.**

So a *conformant* issuer is vulnerable: the security consequence (an attestation issued into
someone else's device) does not follow the regulatory boundary (identity means vs not).

---

## 2. Roles in this run

| Paper (§5.2)                                   | This testbed run |
|------------------------------------------------|------------------|
| **Bob** — authenticates (identity proofing), his attributes are attested | **Bob unit** — "Bob (authenticates as Anna Bianchi)": runs the whole OpenID4VCI authorisation leg (client attestation, DPoP, Keycloak login as `abianchi`). |
| **Alice** — supplies the key the credential binds to; ends up holding it | "Alice (receives the transferred degree)": her device key signs the credential-request proof, so the issuer binds the degree to *her* WSCD. |
| **Attestation Provider** — issues the EAA, checks only device binding | **EUDI reference PID issuer**, issuing the university degree (a non-PID attribute attestation). |

The transfer is the single decision to sign the **key-binding proof** with Alice's device
key while Bob runs the authorisation leg — visible as the `BIND` event below, which carries
*two* device keys: the authorising one and the (different) bound one.

> **Fidelity note.** Both wallet units run in one process with software (emulated) WSCDs.
> This does not flatter the attack: the transfer never extracts or moves a key — Alice's
> key is generated in, and stays in, Alice's unit; only the *proof signed by it* is
> submitted during Bob's session. A genuine WSCD would behave identically, because the
> issuer's checks are all satisfied by a real, non-exportable key in a certified device —
> just the wrong person's device.

---

## 3. The attack, step by step

**Step 1 — Bob starts issuance and authenticates.** Bob's wallet unit runs OpenID4VCI
against the reference issuer: it presents its client attestation and DPoP proof and logs in
as **Anna Bianchi** (`abianchi`). The issuer will attest Anna Bianchi's degree attributes.

**Step 2 — the key-binding proof is signed by Alice.** At the credential request, the
JWT proof of possession — whose embedded key attestation names the device key the credential
will bind to — is signed with **Alice's** device key, not Bob's. This is the whole attack,
and the only thing that differs from an ordinary issuance.

**Step 3 — the issuer binds to Alice's device.** The issuer verifies the proof against the
attested key, verifies the key attestation, and binds the degree's `cnf` to **Alice's** key.
It performs no check relating that key to the authenticating identity (ISSU_05 does not apply
to EAAs). The credential is stored in **Alice's** unit.

**Step 4 — Alice presents it alone.** Alice presents the degree to a verifier with a
key-binding JWT under her own device key. It verifies. Bob is not involved and holds nothing.

---

## 4. Issuance — the transfer (flow `{iss_flow}`)

Bob authenticates; the credential is bound to Alice's device key and stored in Alice's unit.

```
{iss_timeline}
```

After issuance, the degree is in **Alice's** unit (`walletUnitId: {iss_bound_to}`): Alice
holds **{alice_n}** credential, Bob holds **{bob_n}**.

---

## 5. Presentation — Alice alone, Bob absent (flow `{pres_flow}`)

```
{pres_timeline}
```

### Result

```json
{pres_result}
```

`status: {pres_status}` — Alice presented Bob-authenticated attributes on her own device,
under her own WSCD-resident key, and the verifier accepted. Asking **Bob** to present the
same credential returns `status: {bob_pres_status}` (`{bob_pres_error}`): he holds nothing.
The attestation has been *transferred*, not delegated — it works for Alice alone,
indefinitely, without Bob.

---

## 6. What is faithful and what is simplified

- **Faithful.** The reference issuer is unmodified; every device-scoped binding requirement
  (WUA_09a/11a/12) is satisfied, because Alice's key genuinely is in a certified,
  non-exportable WSCD and the wallet genuinely possesses it. The transfer is the single
  decision to sign the key-binding proof with a second unit's key while the first runs the
  authorisation leg — a one-line change in the holder (paper §6).
- **Simplified.** The two units run in one process with emulated WSCDs (see
  `wscd-real-vs-emulated-sdjwt-vc.md`); as argued above, no key moves, so the emulation does
  not weaken the attack. The paper frames the enabling condition as a *decoupled or
  cross-device authorisation flow*; here the split between the authorisation leg (Bob) and
  the key-binding proof (Alice's key) is realised directly in one holder, which is the same
  separation the issuer fails to cross-check.
"""


if __name__ == "__main__":
    sys.exit(main())
