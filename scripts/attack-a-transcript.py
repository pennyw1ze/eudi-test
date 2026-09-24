#!/usr/bin/env python3
"""Run Attack A (presentation-time relay pooling) and emit an annotated transcript.

The attack, from Rufini & Visconti, "Hardware Binding Without Non-Transferability"
(No Pooling, No Party), Section 5.1: two colluding holders jointly satisfy one verifier
request for two credentials, each signing a key-binding JWT with its OWN device (WSCD)
key over the SAME nonce and audience. Every verifier check passes, because SD-JWT VC
binds each credential to the session INDEPENDENTLY — no element of the protocol asserts
that the two signing keys belong to the same holder (paper Section 2.2). The property
this breaks is C5 / non-poolability (Definition 1).

Expects `make up` and `make testbed` already running. Writes docs/attack-a-pooling-transcript.md.

    python3 scripts/attack-a-transcript.py
"""
import json
import os
import sys
import urllib.request

API = os.environ.get("BASE", "http://localhost:4000") + "/api"
PID_CFG = "eu.europa.ec.eudi.pid_vc_sd_jwt"
DEG_CFG = "urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt-compact"
OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "attack-a-pooling-transcript.md")

# The verifier asks for one attribute from each of two different credentials, marked
# required together (credential_sets): birthdate from the PID, graduation date from the
# university degree. Neither, on its own, satisfies the request.
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
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.loads(r.read().decode())


def has_vct(unit_id, frag):
    return any(frag in json.dumps(c) for c in call("GET", "/credentials?walletUnitId=" + unit_id))


def setup():
    """Alice = unit 1 holds the PID; Bob = unit 2 (colluder) holds the degree."""
    units = call("GET", "/wallet-units")
    alice = units[0]["id"]
    bob = units[1]["id"] if len(units) >= 2 else \
        call("POST", "/wallet-units", {"label": "Wallet unit 2 (colluder)"})["id"]
    if not has_vct(alice, "urn:eudi:pid:1"):
        call("POST", "/issue", {"walletUnitId": alice, "credentialConfigurationId": PID_CFG,
                                "username": "tneal", "password": "password"})
    if not has_vct(bob, "learning:credential"):
        call("POST", "/issue", {"walletUnitId": bob, "credentialConfigurationId": DEG_CFG,
                                "username": "abianchi", "password": "password"})
    return alice, bob


def short(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def timeline(flow_id):
    """Merge the crypto (/api/crypto) and network (/api/trace) events for one flow."""
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
                lines.append(f"[{t}] HTTP  wallet -> {e['actor']}: {e.get('method','')} "
                             f"{short(e.get('url',''), 60)} -> {e.get('status','')}{d}")
            elif e["kind"] == "step":
                lines.append(f"[{t}] STEP  {e['actor']}: {e.get('note','')}")
            elif e["kind"] == "error":
                lines.append(f"[{t}] ERROR {e.get('note','')}")
        else:
            lines.append(f"[{t}] {e['operation'].upper():8} {e['actor']}: {e['artifact']}")
            lines.append(f"           {short(e['summary'], 110)}")
            for k in e.get("keys", []):
                lines.append(f"           key[{k.get('role','?')}] {k.get('thumbprint','')[:22]}…")
            for bk, bv in (e.get("binds") or {}).items():
                lines.append(f"           . {bk}: {short(bv, 74)}")
            if e.get("caveat"):
                lines.append(f"           ! {short(e['caveat'], 150)}")
    return "\n".join(lines)


def render_doc(alice, bob, res):
    c = {x["queryId"]: x for x in res.get("contributions", [])}
    pid, deg = c.get("pid", {}), c.get("degree", {})
    tl = timeline(res["flowId"])
    return DOC_TEMPLATE.format(
        flow=res["flowId"],
        status=res["status"],
        pooled=res["pooled"],
        alice=alice, bob=bob,
        pid_unit=pid.get("walletUnitLabel", "?"), pid_key=pid.get("deviceKeyThumbprint", "?"),
        pid_cred=pid.get("credentialId", "?"), pid_vct=pid.get("vct", "?"),
        deg_unit=deg.get("walletUnitLabel", "?"), deg_key=deg.get("deviceKeyThumbprint", "?"),
        deg_cred=deg.get("credentialId", "?"), deg_vct=deg.get("vct", "?"),
        timeline=tl,
        result=json.dumps({k: res.get(k) for k in
                          ("status", "pooled", "contributions", "presentedCredentialIds")}, indent=2),
    )


DOC_TEMPLATE = r"""# Attack A — presentation-time relay pooling — annotated transcript

*Generated by `scripts/attack-a-transcript.py` against the running testbed. Regenerate
after any change to the presentation code so the transcript matches the current build.*

This is a faithful, run-time reproduction of **Attack A** from Rufini & Visconti,
*Hardware Binding Without Non-Transferability: Credential Pooling Attacks on the
European Digital Identity Wallet, and a Legacy-Compatible Defence* ("No Pooling, No
Party"), **Section 5.1**. It is exercised against the **official EUDI reference verifier**
(`eudi-srv-web-verifier-endpoint`), which performs the device-binding check — so this is
not the trivial replay case the paper sets aside, but the real one.

---

## 1. What the attack is (as in the paper)

The EUDI Wallet binds each credential to a public key whose private counterpart lives in
a certified **Wallet Secure Cryptographic Device (WSCD)**, and every presentation carries
a signature under that key. The ARF's stated purpose for this is **user binding** —
assurance that *the entity presenting a credential is its subject* (paper §1).

The paper's thesis is that device binding proves only that *a* certified WSCD
participated, and that the inference from there to *user* binding is unsound. Attack A is
the presentation-time demonstration:

> Alice holds C_A, Bob holds C_B, and a verifier requests both. Alice establishes the
> session, forwards the session transcript (mdoc) or **nonce and audience (SD-JWT)** to
> Bob, who authenticates locally, **signs with his own WSCD key** and returns the
> signature. Alice assembles a response carrying C_A, C_B and **both device signatures**.
> Every verifier check succeeds. Both signatures verify under keys certified as
> WSCD-resident. No key material crosses the channel, so non-extractability is untouched.
> The attack fails only where disclosed attributes overlap on identifying values.
> — paper §5.1

**Threat model** (paper §4.1): two or more *honest-but-colluding* holders, each in sole
control of their own Wallet Unit, want to convince a verifier that a set of credentials
belongs to one person. Holders do **not** extract keys — the WSCD is not compromised.
Issuers, the Wallet Provider and verifiers all follow the protocol. Holders may
communicate out of band within the session timeout. This is a *holder-side* adversary,
the case existing EUDI privacy analysis tends to dismiss.

### Why it violates the protocol

The mechanism is a specific gap, not a bug:

- An SD-JWT VC presentation carries a **per-credential key-binding JWT over a nonce and
  audience**. When several credentials are presented together, each is bound to the
  session **independently — no element of the protocol asserts a relationship between the
  signers** (paper §2.2). There is nowhere in the response, and nothing in the verifier
  procedure, that says "these two keys belong to the same holder."
- The verifier does everything the specification asks: it checks each issuer signature,
  checks the selective-disclosure digests, and verifies each key-binding JWT under a key
  certified as WSCD-resident. All of that passes for a response whose two credentials
  were signed by **two different people on two different devices**.
- The security property this breaks is **C5 / non-poolability** (Definition 1): *a
  verifier requesting several credentials should be able to determine that they belong to
  one holder.* Here it cannot. (Device-binding verification is itself only a SHOULD —
  ARF OIA_17 — but the attack targets a verifier that performs it, and succeeds anyway.)

The testbed reproduces exactly this: a combined request for two credentials, satisfied by
two wallet units, each signing its own key-binding JWT with its own device key over the
one shared nonce and audience, accepted as a single presentation.

---

## 2. Roles in this run

| Paper (§5.1)                          | This testbed run |
|---------------------------------------|------------------|
| **Alice** — holder A, holds `C_A`, key `pk_A`; establishes the session (the "front") | **{pid_unit}** (`{alice}`) — holds the **PID** (`{pid_vct}`), device key `{pid_key}`. Drives the OpenID4VP exchange and posts the combined `vp_token`. |
| **Bob** — holder B, holds `C_B`, key `pk_B`; authenticates locally and signs with his own WSCD key | **{deg_unit}** (`{bob}`) — holds the **university degree** (`{deg_vct}`), device key `{deg_key}`. Signs its own key-binding JWT for its credential. |
| **Verifier / Relying Party** — requests both credentials, verifies each | **EUDI reference verifier**, client id `x509_san_dns:localhost`. |
| **Shared session material** forwarded A → B (nonce + audience for SD-JWT) | The verifier's `nonce` and `audience`, which *both* units sign over — visible in the two `SIGN` events below. |

The two device keys — `{pid_key}` and `{deg_key}` — are the crux: two distinct
WSCD-resident keys, one accepted response.

> **Fidelity note.** In the paper Alice and Bob are separate parties relaying over an
> out-of-band channel. This testbed runs both wallet units in one process and has each
> sign with its own device key, so there is no literal network relay — but the object the
> verifier receives and checks is byte-for-byte the Attack A response: two credentials,
> two independent WSCD-resident key-binding signatures, one nonce and audience. The WSCD
> is emulated in software here (see `wscd-real-vs-emulated-sdjwt-vc.md`); the paper's
> argument is explicitly that a *genuine, non-extractable* WSCD does not prevent this,
> because no key ever needs to move — so the emulation does not flatter the attack.

---

## 3. The attack, step by step

**Setup.** {pid_unit} is issued a PID; {deg_unit} is issued a university degree. The two
credentials belong to two different holders and are bound to two different device keys.

**Step 1 — the verifier asks for both credentials.** The relying party opens a
presentation transaction whose DCQL lists two credentials in one required
`credential_sets` option: `birthdate` from the PID and `date_of_issuance` (graduation
date) from the degree. Neither credential alone satisfies the request.

**Step 2 — the front unit accepts the signed request.** {pid_unit} fetches the signed
authorisation request (JAR), verifies the verifier's signature, and reads the **nonce**
and **audience**. In the paper this is the session material Alice forwards to Bob.

**Step 3 — each holder signs its own credential (the pooling step).** For the `pid`
query, {pid_unit} signs a key-binding JWT with **its** device key (`{pid_key}`). For the
`degree` query, {deg_unit} signs a key-binding JWT with **its** device key (`{deg_key}`).
Both signatures are over the **same** nonce and audience. This is the moment two
different holders' keys enter one response.

**Step 4 — one combined response is posted.** The front unit assembles a single
`vp_token` carrying both credentials (keyed by query id) and both key-binding JWTs, and
posts it in one `direct_post`. From the verifier's side this is one presentation from one
wallet.

**Step 5 — the verifier accepts.** It verifies each issuer signature, each disclosure
digest, and each key-binding JWT under its WSCD-resident key — all valid — and accepts.
It has no means to notice that the two credentials came from two holders. **C5 /
non-poolability is violated.**

---

## 4. Transcript (flow `{flow}`)

Merged cryptographic and network timeline for the one pooled presentation. `SIGN`/`VERIFY`
lines are cryptographic events; `HTTP` lines are the exchanges on the wire; `STEP` lines
are narrative markers. `!` marks a recorded caveat.

```
{timeline}
```

### Result

```json
{result}
```

`status: {status}`, `pooled: {pooled}` — the reference verifier accepted a single
presentation whose two credentials were signed by two different device keys belonging to
two different wallet units. That is Attack A: hardware binding held (no key moved, each
signature is valid under a certified key), and it still did not deliver user binding.
"""


def main():
    alice, bob = setup()
    res = call("POST", "/present/pooled", {"dcqlQuery": HR_DCQL, "walletUnitIds": [alice, bob]})
    if not res.get("pooled"):
        print("WARNING: presentation was not pooled — check setup.", file=sys.stderr)
    doc = render_doc(alice, bob, res)
    path = os.path.abspath(OUT)
    with open(path, "w") as f:
        f.write(doc)
    print("wrote", path)
    print("status:", res.get("status"), "pooled:", res.get("pooled"))
    return 0 if res.get("pooled") and res.get("status") == "presented" else 1


if __name__ == "__main__":
    sys.exit(main())
