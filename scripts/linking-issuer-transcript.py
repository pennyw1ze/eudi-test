#!/usr/bin/env python3
"""Run the linking-issuer countermeasure and emit an annotated transcript.

The countermeasure, from Rufini & Visconti, "Hardware Binding Without
Non-Transferability" (No Pooling, No Party), Section "The linking issuer role": a party
positioned to observe co-residency issues a single-use LINK CREDENTIAL binding the keys
of a holder's credentials, and the verifier — with three ordinary signature checks and an
equality test — establishes same-holder possession. This restores C5 / non-poolability
(Definition 1) against Attack A, without changing the WSCD (C1), the credential formats
(C2), or the kind of verification a relying party does (C3), and without giving up
verifier unlinkability (C4).

This testbed instantiates the linking issuer as a DEDICATED AUTHORITY (paper
Instantiation 3): a standalone party on the verifier's trusted list, separate from the
credential issuers and the wallet provider, chosen so the Commission's reference issuer
and verifier stay unmodified.

Expects `make up` and a running testbed on :4000. Writes docs/linking-issuer-transcript.md.

    python3 scripts/linking-issuer-transcript.py
"""
import json
import os
import sys
import time
import urllib.request

API = os.environ.get("BASE", "http://localhost:4000") + "/api"
PID_CFG = "eu.europa.ec.eudi.pid_vc_sd_jwt"
DEG_CFG = "urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt-compact"
OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "linking-issuer-transcript.md")
N = 3  # batch size

HR_DCQL = {
    "credentials": [
        {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]},
         "claims": [{"path": ["birthdate"]}]},
        {"id": "degree", "format": "dc+sd-jwt",
         "meta": {"vct_values": ["urn:eu.europa.ec.eudi:learning:credential:1"]},
         "claims": [{"path": ["date_of_issuance"]}]},
    ],
    "credential_sets": [{"options": [["pid", "degree"]], "required": True,
                         "purpose": "graduation-speed check: birthdate (PID) + graduation date (degree)"}],
}


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read().decode())


def add_unit(label):
    return call("POST", "/wallet-units", {"label": label})["id"]


def issue(unit, cfg, user, copies=1):
    for _ in range(3):
        r = call("POST", "/issue", {"walletUnitId": unit, "credentialConfigurationId": cfg,
                                    "username": user, "password": "password",
                                    "autoLogin": True, "copies": copies})
        if r.get("status") == "issued":
            return r
        time.sleep(3)
    raise SystemExit(f"issuance failed {cfg}/{user}: {json.dumps(r)[:300]}")


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
                             f"{short(e.get('url',''), 58)} -> {e.get('status','')}{d}")
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


def link_summary(res):
    link = res.get("link") or {}
    return {
        "status": res.get("status"),
        "link": {
            "requested": link.get("requested"),
            "issued": link.get("issued"),
            "accepted": link.get("accepted"),
            "reason": link.get("reason"),
            "linkedKeyThumbprints": link.get("linkedKeyThumbprints"),
            "presentedKeyThumbprints": link.get("presentedKeyThumbprints"),
            "linkingIssuer": link.get("linkingIssuer"),
        },
        "contributions": [
            {"queryId": c["queryId"], "walletUnitLabel": c["walletUnitLabel"],
             "deviceKeyThumbprint": c["deviceKeyThumbprint"]}
            for c in res.get("contributions", [])
        ],
    }


def main():
    # -- single-issuance units ------------------------------------------------
    genuine = add_unit("Holder (genuine, both creds)")
    col_a = add_unit("Colluder A (PID)")
    col_b = add_unit("Colluder B (degree)")
    issue(genuine, PID_CFG, "tneal")
    issue(genuine, DEG_CFG, "tneal")
    issue(col_a, PID_CFG, "tneal")
    issue(col_b, DEG_CFG, "abianchi")

    # -- batch-issuance units -------------------------------------------------
    batch = add_unit("Holder (batch, both creds x%d)" % N)
    bcol_a = add_unit("Batch colluder A (PID x%d)" % N)
    bcol_b = add_unit("Batch colluder B (degree x%d)" % N)
    issue(batch, PID_CFG, "jkowalski", N)
    issue(batch, DEG_CFG, "jkowalski", N)
    issue(bcol_a, PID_CFG, "jkowalski", N)
    issue(bcol_b, DEG_CFG, "abianchi", N)

    # -- flows ----------------------------------------------------------------
    g = call("POST", "/present/linked", {"walletUnitIds": [genuine], "dcqlQuery": HR_DCQL})
    ref = call("POST", "/present/pooled", {"walletUnitIds": [col_a, col_b], "dcqlQuery": HR_DCQL})
    p = call("POST", "/present/linked", {"walletUnitIds": [col_a, col_b], "dcqlQuery": HR_DCQL})
    bg1 = call("POST", "/present/linked", {"walletUnitIds": [batch], "dcqlQuery": HR_DCQL})
    bg2 = call("POST", "/present/linked", {"walletUnitIds": [batch], "dcqlQuery": HR_DCQL})
    bp = call("POST", "/present/linked", {"walletUnitIds": [bcol_a, bcol_b], "dcqlQuery": HR_DCQL})

    def keys(res):
        return (res.get("link") or {}).get("linkedKeyThumbprints", [])

    # Explicit replacement (not str.format): the prose contains literal braces such as
    # `Sign_LI({pk_1, pk_2})` that str.format would try to interpret as fields.
    fields = {
        "li": (g.get("link") or {}).get("linkingIssuer", "?"),
        "g_flow": g["flowId"], "g_timeline": timeline(g["flowId"]),
        "g_result": json.dumps(link_summary(g), indent=2, ensure_ascii=False),
        "ref_status": ref.get("status"), "ref_pooled": ref.get("pooled"),
        "p_flow": p["flowId"], "p_timeline": timeline(p["flowId"]),
        "p_result": json.dumps(link_summary(p), indent=2, ensure_ascii=False),
        "bg1_keys": ", ".join(k[:10] for k in keys(bg1)) or "-",
        "bg2_keys": ", ".join(k[:10] for k in keys(bg2)) or "-",
        "bg1_status": bg1.get("status"), "bg2_status": bg2.get("status"),
        "bp_status": bp.get("status"),
        "bp_reason": (bp.get("link") or {}).get("reason", "?"),
        "bp_result": json.dumps(link_summary(bp), indent=2, ensure_ascii=False),
        "rotated": set(keys(bg1)) != set(keys(bg2)),
    }
    doc = DOC_TEMPLATE
    for k, v in fields.items():
        doc = doc.replace("{" + k + "}", str(v))
    path = os.path.abspath(OUT)
    with open(path, "w") as f:
        f.write(doc)
    print("wrote", path)
    ok = (g.get("status") == "presented" and (g.get("link") or {}).get("accepted")
          and ref.get("status") == "presented"
          and p.get("status") == "rejected" and not (p.get("link") or {}).get("accepted")
          and bg1.get("status") == "presented" and bg2.get("status") == "presented"
          and set(keys(bg1)) != set(keys(bg2))
          and bp.get("status") == "rejected")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


DOC_TEMPLATE = r"""# The linking-issuer countermeasure — annotated execution transcript

*Generated by `scripts/linking-issuer-transcript.py` against the running testbed.
Regenerate after any change to the presentation, linking-issuer or verifier code so the
transcript matches the current build.*

This is a faithful, run-time reproduction of the **defence** from Rufini & Visconti,
*Hardware Binding Without Non-Transferability: Credential Pooling Attacks on the European
Digital Identity Wallet, and a Legacy-Compatible Defence* ("No Pooling, No Party"),
**Section "The linking issuer role"**. It is exercised against the **official EUDI
reference issuer and verifier**, both unmodified: the reference verifier performs its
ordinary checks (issuer signatures, disclosure digests, key-binding/device signatures,
status), and a thin verifier-side extension adds the two extra steps the countermeasure
needs. It defends against **Attack A** (presentation-time relay pooling), whose own
transcript is in `attack-a-pooling-transcript.md`.

---

## 1. What the countermeasure is (as in the paper)

Attack A works because, at presentation time, **batch issuance has severed every value
two credentials could share**: each credential copy carries an independent key, so two
credentials in one response share nothing a verifier could check, and nothing in the
SD-JWT VC response asserts that the two signing keys belong to one holder (paper
§2.2, §"Why the obvious fix is unavailable"). A same-key check is not merely unimplemented
but *structurally impossible* — that is Lemma "tension".

The paper's escape is to **move the observation in time rather than in computation**. The
comparison of two keys must happen where they are *already* jointly observable, which at
presentation is nowhere but at **issuance** is routine (the WUA already assures an issuer
that a credential key is co-resident in a given WSCD). A **link credential** is a one-time
transfer of that fact:

> A party LI that can (i) validate a WUA, (ii) obtain per-key attestation that a public
> key is co-resident with the WUA key, and (iii) issue credentials recognised through a
> trusted list, issues `link = Sign_LI({pk_1, pk_2})`. At presentation the wallet sends
> the two credentials, the link credential, and both device signatures over the session
> transcript. The verifier verifies issuer A's signature and extracts `pk_1`; verifies
> issuer B's and extracts `pk_2`; verifies LI's signature on `link` and checks its
> contents equal `{pk_1, pk_2}`; verifies both device signatures; checks all three
> signers against trusted lists; checks revocation. — paper §"The linking issuer role"

This keeps all five properties: **C1** (WSCD does only ECDSA — the link check is three
signature verifications and an equality test), **C2** (credential formats unchanged),
**C3** (the verifier still only verifies signatures), **C4** (verifier unlinkability — the
link credential is single-use and carries no value reused across sessions), and restores
**C5** (non-poolability).

### Why it defeats Attack A

The load-bearing fact is **co-residency under one WUA**. A genuine holder's two
credentials are bound to keys in the *same* WSCD, so one WUA can attest both, and the
linking issuer binds them. Two *pooled* credentials come from two different wallet units —
two different WSCDs, two different WUAs — and **no single WUA can prove possession of both
device keys**, so co-residency cannot be certified, no link credential exists over the
pair, and the verifier rejects. The relation the verifier checks ("a link credential
exists over exactly this pair") is decidable only when the credential is supplied, so
colluding verifiers holding two keys from separate sessions cannot evaluate it — C4 is
preserved (paper Prop. "escape").

---

## 2. Instantiation and roles in this run

The linking issuer is instantiated here as a **dedicated authority** (paper
Instantiation 3): `{li}` — a standalone party with its own signing key and a self-signed
certificate on the verifier's trusted list, distinct from the credential issuers and the
wallet provider. This choice keeps the Commission's reference issuer and verifier
unmodified; Instantiation 1 (an existing credential issuer emits the link as a by-product)
or Instantiation 2 (the wallet provider) would change those services, and are a wiring
change away — the security demonstration is identical, they differ only in the trust and
privacy profile of assumption `as:li`.

| Paper (§"The linking issuer role")            | This testbed run |
|-----------------------------------------------|------------------|
| **Holder** with credentials `C_A`, `C_B` bound to keys `pk_1`, `pk_2` co-resident in one WSCD | A **wallet unit** holding both the PID and the university degree, each bound to a device key in that one unit. |
| **Issuers A, B** binding `pk_1`, `pk_2` | The **reference PID issuer** and the **reference attestation (degree) issuer**. |
| **Linking issuer LI** — validates WUAs, attests co-residency, issues `link = Sign_LI({pk_1,pk_2})` | `{li}` — verifies each unit's WUA co-residency attestation (with per-key proof of possession) and, only if all keys fall under one WUA, issues a single-use link credential. |
| **Verifier** — steps 1–6, including the link check | **EUDI reference verifier** (steps 1, 2, 5, 6) + a verifier-side extension (steps 3–4). |

> **Fidelity note.** The WSCD is emulated in software (see
> `wscd-real-vs-emulated-sdjwt-vc.md`). The countermeasure does not depend on the
> emulation: what makes co-residency uncertifiable for a pooled pair is the **proof of
> possession** the linking issuer demands per key — a wallet unit can only sign a proof
> for a key whose private half it holds, exactly as a real WSCD would gate that signature.
> Two units therefore always produce two WUAs, on emulated or genuine hardware alike.

---

## 3. The countermeasure, step by step

**Phase 0–2 (setup).** Each wallet unit is provisioned and issued its credentials by the
reference issuer in the ordinary way; each credential is bound to a device key in that
unit's WSCD.

**Phase 3 input — co-residency attestation.** For a presentation, each contributing unit
signs, under its WUA, a statement that the key it will present with is co-resident in its
WSCD, carrying a fresh **proof of possession** per key over the presentation's nonce.

**Phase 3 — link issuance.** The linking issuer verifies every attestation's WUA
signature and every proof of possession, groups the keys by WUA, and issues a single-use
link credential over the keys **only if they all fall under one WUA**. Otherwise it
refuses.

**Phase 4 — presentation.** The wallet posts the ordinary combined `vp_token` (which the
reference verifier checks as always) together with the link credential.

**Verifier steps 3–4.** The verifier reads the `cnf` keys off the presented credentials,
verifies the linking issuer's signature against its trusted list, and checks the link
credential covers **exactly** those keys. Accept only if it does.

---

## 4. Genuine holder — accepted (flow `{g_flow}`)

One wallet unit holds both the PID and the degree, each bound to a key in its own WSCD.
The two keys are co-resident, so the linking issuer binds them and the verifier accepts.

```
{g_timeline}
```

### Result

```json
{g_result}
```

`status: presented`, `link.accepted: true` — a trusted linking issuer certified that the
two presented credentials' keys are co-resident in one WSCD, and the verifier's link check
passed. A genuine holder is unaffected by the defence.

---

## 5. Pooled presentation (Attack A) — rejected (flow `{p_flow}`)

The same combined request, now answered by **two** colluding units (PID from one, degree
from the other). For reference, the *unmodified* verifier alone still accepts this exact
`vp_token` — `/present/pooled` returns `status: {ref_status}`, `pooled: {ref_pooled}`
(that is Attack A). With the countermeasure, the linking issuer is asked to bind the two
keys and **refuses**, because they were attested under two distinct WUAs:

```
{p_timeline}
```

### Result

```json
{p_result}
```

`status: rejected`, `link.accepted: false` — the two device keys are attested under two
distinct WUAs, so co-residency cannot be certified, no link credential is issued, and the
verifier rejects. **C5 / non-poolability is restored:** the pooled response the reference
verifier accepted on its own is now caught.

---

## 6. Batch issuance — the paper's tension, resolved

Batch issuance is what makes the naive fix impossible: each copy is bound to a **distinct**
key, so two credentials share no value a same-key check could use (paper §"Why the obvious
fix is unavailable"). This run batch-issues {n} copies of each credential and presents
twice from one genuine holder:

| presentation | status | linked keys (first 10 chars) |
|--------------|--------|------------------------------|
| run 1        | `{bg1_status}` | `{bg1_keys}` |
| run 2        | `{bg2_status}` | `{bg2_keys}` |

Both are accepted, each links **two distinct keys** (not one shared device key), and the
two runs use **different key pairs** — the single-use rotation that gives verifier
unlinkability (C4). The link credential certifies co-residency of those distinct keys, so
C5 holds even though the credentials share no value: exactly the tension the paper
resolves by moving the observation to issuance time. Fresh key pair each run: `{rotated}`.

A **pooled batch** (two batch-issued units) is still rejected — `status: {bp_status}`,
reason *"{bp_reason}"*:

```json
{bp_result}
```

---

## 7. What is faithful and what is simplified

- **Faithful.** The reference issuer and verifier are unmodified; the link check is three
  signature verifications and an equality test (C1–C3); the co-residency decision rests on
  a per-key proof of possession, so two WSCDs always yield two WUAs; link credentials are
  single-use and bound to the presentation nonce (C4); pooling is rejected and genuine
  holders accepted (C5).
- **Simplified.** (i) The linking issuer is a dedicated authority (Instantiation 3) rather
  than the recommended Instantiation 1; a wiring change. (ii) The link credential is issued
  **on demand** at presentation over the two selected copies, rather than pre-issued
  per index at issuance (paper Phase 3); equivalent security and single-use, but the LI is
  contacted per presentation. (iii) The link credential is a plain JWS listing the linked
  keys; the paper's k>2 SD-JWT form with selectively-disclosable per-key claims and decoy
  digests (§"Extension to k credentials") — a privacy refinement, not a security
  requirement — is not implemented.
""".replace("{n}", str(N))


if __name__ == "__main__":
    sys.exit(main())
