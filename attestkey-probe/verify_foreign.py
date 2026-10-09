#!/usr/bin/env python3
"""Did Alice get her attest key to certify Bob's key?

Reads Bob's and Alice's results from the foreign-key probe. Bob's key must be genuine and
non-exportable; then, for every certificate Alice ended up holding, it checks whether the
certificate carries Bob's public key AND is signed by Alice's AK. Any such certificate would
let Alice prove Bob's key "co-resident" with her own keys.

Usage: verify_foreign.py BOB.json ALICE.json
"""
import json
import sys
from pathlib import Path

from cryptography import x509

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_attestkey import (ECDSA_SHA256, GENERATED, ORIGIN, Report, b64d, certs,  # noqa: E402
                              chain_to_google, der, key_description, load_roots, signed_by, spki)


def main(bob_path, alice_path):
    roots = load_roots()
    bob = json.loads(Path(bob_path).read_text())
    alice = json.loads(Path(alice_path).read_text())
    report = Report()

    print("== Bob's key (what Bob can hand over: public key and attestation chain)")
    bob_chain = certs(bob["chain"])
    bob_spki = spki(bob_chain[0])
    ok, why = chain_to_google(bob_chain, roots)
    report.check(ok, f"Bob's attestation chain ({len(bob_chain)} certificates) {why}")
    d = key_description(bob_chain[0])
    report.check(d is not None and d["origin"] == GENERATED,
                 f"Bob's key origin = {ORIGIN.get(d and d['origin'])}, level {bob['level']}")
    report.check(not bob["export_getEncoded"].startswith("EXPORTED"),
                 f"Bob cannot read his private key: {bob['export_getEncoded']}")
    report.check(not bob["export_pkcs8"].startswith("EXPORTED"),
                 f"Bob cannot export it as PKCS#8: {bob['export_pkcs8'][:110]}")

    print("\n== Alice's attempts to have her AK certify Bob's key")
    ak = certs(alice["ak_chain"])[0]
    report.check(not alice["route1_outcome"].startswith("SIGNED"),
                 f"route 1, AK signs a certificate body with Bob's key: {alice['route1_outcome'][:120]}")
    report.check(not alice["route2_generated_key_is_bobs"],
                 "route 2, a key generated under the AK is never Bob's key")
    Report.note(f"generation API attestation setters: {', '.join(alice['keygen_attestation_setters'])}")
    report.check(not alice["import_attestation_setters"],
                 f"route 3, the import API has no attestation parameter "
                 f"({', '.join(alice['import_attestation_setters']) or 'none'})")
    Report.note(f"import of Alice's software key stored with Bob's chain: {alice['route3_outcome'][:120]}")

    print("\n== Every certificate Alice holds")
    held = [("route 2 (AK-attested key)", c) for c in certs(alice.get("route2_chain", []))]
    held += [("route 3 (imported entry)", c) for c in certs(alice.get("route3_chain", []))]
    if alice.get("route1_signature"):
        body = b64d(alice["route1_tbs"]) + ECDSA_SHA256 + der(0x03, b"\x00" + b64d(alice["route1_signature"]))
        held.append(("route 1 (AK-signed body)", x509.load_der_x509_certificate(der(0x30, body))))
    hits = []
    for name, c in held:
        carries, by_ak = spki(c) == bob_spki, signed_by(c, ak.public_key())
        Report.note(f"{name}: carries Bob's key {carries}, signed by Alice's AK {by_ak}")
        if carries and by_ak:
            hits.append(name)
    report.check(not hits, "no certificate Alice holds carries Bob's key under her AK's signature")

    print(f"\n{'ALL CHECKS PASSED' if report.failures == 0 else f'{report.failures} CHECK(S) FAILED'}")
    return 0 if report.failures == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
