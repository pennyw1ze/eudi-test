#!/usr/bin/env python3
"""Can an attest key (AK) created now certify a key that already existed?

Reads the two stages of the late-attestation probe (late.sh). The setup stage generated, per
security level, an "old" and a "regen" key with the platform's usual attestation, before any AK
existed. The attest stage, later and in a new process, created a fresh AK and tried every route
to an AK-signed attestation for those keys:
  1. the AK signs a certificate body carrying the old key;
  2. export the old key (re-importing it anywhere needs the private key);
  3. copy the old key's keystore entry to a new alias;
  4. keystore2's binder interface directly: generateKey with the AK (control), importKey with
     the AK, without it, and with it but no attestation challenge;
  5. generate under the regen key's alias with the AK.
It passes when every route is refused or yields a certificate for some other key, and no
certificate from the attest stage carries a pre-existing key under the AK's signature.

Usage: verify_late.py SETUP.json ATTEST.json
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_attestkey import (ATTEST_KEY, ECDSA_SHA256, GENERATED, KEY_DESCRIPTION, ORIGIN,  # noqa: E402
                              SECURITY_LEVEL, Report, authorizations, b64d, certs, chain_to_google,
                              der, fingerprint, items, key_description, load_roots, signed_by, spki, tlv)

TAG_CREATION_DATETIME = 701


def created(cert):
    """CREATION_DATETIME of the attested key (keystore2 adds it; software-enforced)."""
    try:
        raw = cert.extensions.get_extension_for_oid(KEY_DESCRIPTION).value.value
    except x509.ExtensionNotFound:
        return None
    fields = items(tlv(raw)[1])
    for auth in (fields[6][1], fields[7][1]):
        value = authorizations(auth).get(TAG_CREATION_DATETIME)
        if value is not None:
            return datetime.fromtimestamp(int.from_bytes(value, "big") / 1000, tz=timezone.utc)
    return None


def split_chain(blob):
    """keystore2 returns the chain above the leaf as concatenated DER certificates."""
    out, i = [], 0
    while i < len(blob):
        _, _, j = tlv(blob, i)
        out.append(x509.load_der_x509_certificate(blob[i:j]))
        i = j
    return out


def verifies(spki_der, message, signature):
    try:
        serialization.load_der_public_key(spki_der).verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def origin_of(cert, binder_result=None):
    d = key_description(cert) if cert is not None else None
    if d is not None:
        return d["origin"]
    o = (binder_result or {}).get("origin")
    return o["origin"] if o else None


def issuer_name(leaf, chain, ak):
    if signed_by(leaf, ak.public_key()):
        return "the fresh AK"
    if signed_by(leaf, leaf.public_key()):
        return "itself (self-signed: no attestation key involved)"
    if chain and signed_by(leaf, chain[0].public_key()):
        return f"{chain[0].subject.rfc4514_string()[:70]} (key {fingerprint(chain[0])})"
    return f"unknown issuer {leaf.issuer.rfc4514_string()[:70]}"


def binder_routes(b, ak, old_spki, report, held):
    if "error" in b:
        report.check(False, f"route 4 not run: {b['error'][:120]}")
        return
    results = {}
    for name in ("generate_with_ak", "import_with_ak", "import_without_ak", "import_with_ak_no_challenge"):
        r = b[name]
        leaf = x509.load_der_x509_certificate(b64d(r["certificate"])) if "certificate" in r else None
        rest = split_chain(b64d(r["certificate_chain"])) if "certificate_chain" in r else []
        results[name] = (r, leaf, rest)
        if leaf is not None:
            held.append((f"route 4 {name}", leaf))
        o = origin_of(leaf, r)
        desc = (f"{r['outcome'][:100]}"
                + (f"; certificate signed by {issuer_name(leaf, rest, ak)}" if leaf is not None else "")
                + (f"; origin {ORIGIN.get(o, o)}" if o is not None else ""))
        Report.note(f"route 4 {name.replace('_', ' ')}: {desc}")

    r, leaf, _ = results["generate_with_ak"]
    report.check(leaf is not None and signed_by(leaf, ak.public_key()) and origin_of(leaf, r) == GENERATED
                 and spki(leaf) != old_spki,
                 "route 4 control: keystore2 generateKey with the AK descriptor gives an AK-signed attestation "
                 "of a NEW key, origin GENERATED (so the descriptor does reach the AK)")
    r, leaf, _ = results["import_with_ak"]
    report.check(leaf is None or not signed_by(leaf, ak.public_key()),
                 "route 4: keystore2 importKey with the AK as attestation key does NOT give an AK-signed certificate")
    if leaf is not None and spki(leaf) != b64d(b["imported_spki"]):
        report.check(False, "route 4: the imported key's certificate carries the imported key")
    r_ak, leaf_ak, rest_ak = results["import_with_ak"]
    r_no, leaf_no, rest_no = results["import_without_ak"]
    if leaf_ak is not None and leaf_no is not None:
        same = issuer_name(leaf_ak, rest_ak, ak) == issuer_name(leaf_no, rest_no, ak)
        Report.note(f"route 4: import with and without the AK yields the same issuer: {same} "
                    "(the attestation key argument has no effect)")
    elif r_ak["outcome"] == r_no["outcome"] or (r_ak.get("error_code") is not None
                                                 and r_ak.get("error_code") == r_no.get("error_code")):
        Report.note("route 4: import with and without the AK fails the same way (the AK argument has no effect)")
    r, leaf, _ = results["import_with_ak_no_challenge"]
    if r["outcome"] == "OK":
        Report.note("route 4: import with the AK but no challenge succeeded; KeyMint must refuse that "
                    "(INVALID_ARGUMENT) if it receives an attestation key, so keystore2 did not pass the AK on")


def main(setup_path, attest_path):
    roots = load_roots()
    setup = json.loads(Path(setup_path).read_text())
    attest = json.loads(Path(attest_path).read_text())
    report = Report()
    message = b64d(attest["message"])
    t_setup = datetime.fromtimestamp(setup["run_id"] / 1000, tz=timezone.utc)
    t_attest = datetime.fromtimestamp(attest["run_id"] / 1000, tz=timezone.utc)
    dev = attest["device"]
    print(f"{dev['manufacturer']} {dev['model']}, Android {dev['release']} (API {dev['sdk']}, "
          f"patch {dev['security_patch']})")
    print(f"setup stage {t_setup:%Y-%m-%d %H:%M:%S} UTC, attest stage {t_attest:%H:%M:%S} UTC "
          f"({(t_attest - t_setup).total_seconds() / 60:.1f} min later, new process)")

    print("\n== What the app can call")
    surface = attest.get("binder_surface", {})
    Report.note(f"public generation API attestation setters: {', '.join(attest['keygen_attestation_setters'])}")
    report.check(not attest["import_attestation_setters"],
                 f"public import API attestation setters: {', '.join(attest['import_attestation_setters']) or 'none'}")
    if surface.get("available"):
        for iface in ("IKeystoreService", "IKeystoreSecurityLevel"):
            Report.note(f"keystore2 {iface}: {'; '.join(surface[iface])}")
        taking_ak = [m for m in surface["IKeystoreSecurityLevel"] if m.count("KeyDescriptor") >= 2
                     and not m.startswith("importWrappedKey")]
        Report.note(f"keystore2 calls taking an attestation key: {', '.join(taking_ak)} (both create a key)")
    else:
        report.check(False, f"keystore2 binder interface not reachable: {surface.get('error', '?')[:120]}")
    if isinstance(surface.get("IKeyMintDevice"), list):
        Report.note(f"KeyMint IKeyMintDevice (framework copy of the HAL interface): {'; '.join(surface['IKeyMintDevice'])}")
    for instance in ("default", "strongbox"):
        status = surface.get(f"keymint_hal_{instance}", "not recorded")
        report.check(status.startswith("not reachable"),
                     f"KeyMint HAL '{instance}' from the app: {status} (only keystore2 talks to KeyMint)")

    for name, s in setup["levels"].items():
        a = attest["levels"].get(name, {})
        print(f"\n== {name}")
        if "error" in a:
            report.check(False, a["error"])
            continue
        old_chain = certs(s["old"]["chain"])
        old, old_spki = old_chain[0], spki(old_chain[0])
        regen_before = certs(a["regen_chain_before"])[0]
        regen_spki = spki(regen_before)
        old_d = key_description(old)

        ok, why = chain_to_google(old_chain, roots)
        report.check(ok and old_d is not None and old_d["origin"] == GENERATED
                     and old_d["keymint_security_level"] == (2 if name == "strongbox" else 1),
                     f"old key: hardware key, origin {ORIGIN.get(old_d and old_d['origin'])}, "
                     f"{SECURITY_LEVEL.get(old_d and old_d['keymint_security_level'])}, platform attestation chain {why}")
        report.check(certs(a["old_chain"])[0] == old, "old key's stored certificate unchanged since the setup stage")
        report.check(verifies(old_spki, message, b64d(a["old_signature"])),
                     "old key still signs in the attest stage (the app holds and controls it)")

        ak_chain = certs(a["ak"]["chain"])
        ak, akd = ak_chain[0], key_description(ak_chain[0])
        report.check(chain_to_google(ak_chain, roots)[0] and akd is not None and akd["purposes"] == [ATTEST_KEY]
                     and akd["origin"] == GENERATED,
                     f"fresh AK: genuine attest key (Google chain, purposes {{ATTEST_KEY}}, GENERATED), key {fingerprint(ak)}")
        c_old, c_ak = created(old), created(ak)
        report.check(c_old is not None and c_ak is not None and c_old < c_ak,
                     f"AK created after the old key ({c_old and f'{c_old:%H:%M:%S}'} < {c_ak and f'{c_ak:%H:%M:%S}'} UTC)")
        tmpl = certs(a["template"]["chain"])[0]
        report.check(signed_by(tmpl, ak.public_key()) and key_description(tmpl)["origin"] == GENERATED,
                     "control: a key generated under the AK gets an AK-signed attestation, origin GENERATED")

        held = [("control key", tmpl)]
        print("   routes to an AK-signed attestation for a pre-existing key")
        r = a["route_sign"]
        forged_valid = False
        if r.get("signature"):
            body = b64d(r["tbs"]) + ECDSA_SHA256 + der(0x03, b"\x00" + b64d(r["signature"]))
            forged = x509.load_der_x509_certificate(der(0x30, body))
            forged_valid = signed_by(forged, ak.public_key())
            held.append(("route 1 AK-signed body", forged))
        report.check(not forged_valid, f"route 1, AK signs a certificate body carrying the old key: {r['outcome'][:110]}")

        r = a["route_export"]
        report.check(not r["getEncoded"].startswith("EXPORTED") and not r["pkcs8"].startswith("EXPORTED"),
                     f"route 2, the old key cannot be exported (getEncoded {r['getEncoded']}; PKCS#8 {r['pkcs8'][:70]})")

        r = a["route_copy"]
        if "chain" in r:
            held += [("route 3 copied entry", c) for c in certs(r["chain"])]
        Report.note(f"route 3, copy the old key's entry to a new alias: {r['outcome'][:120]}")

        if "binder" in a:
            binder_routes(a["binder"], ak, old_spki, report, held)

        r = a["route_regenerate"]
        if "chain" in r:
            new = certs(r["chain"])[0]
            held.append(("route 5 regenerated alias", new))
            sig = b64d(r["signature"])
            report.check(signed_by(new, ak.public_key()) and spki(new) != regen_spki
                         and verifies(spki(new), message, sig) and not verifies(regen_spki, message, sig),
                         "route 5, generating under the regen key's alias with the AK REPLACES the key: the AK "
                         f"attests a new key ({fingerprint(new)} != {fingerprint(regen_before)}), the old one no longer signs")
        else:
            Report.note(f"route 5: {r['outcome'][:120]}")

        hits = [what for what, c in held if spki(c) in (old_spki, regen_spki) and signed_by(c, ak.public_key())]
        report.check(not hits, f"none of the {len(held)} certificates the attest stage produced carries a "
                               "pre-existing key under the AK's signature" + (f" (found: {', '.join(hits)})" if hits else ""))

    print(f"\n{'ALL CHECKS PASSED' if report.failures == 0 else f'{report.failures} CHECK(S) FAILED'}")
    return 0 if report.failures == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
