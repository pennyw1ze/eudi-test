#!/usr/bin/env python3
"""Check an attest-key probe result: are two keys provably co-resident in one KeyMint?

For each security level in a JSON written by the probe app:
  1. the attest key (AK) chain verifies up to a Google attestation root;
  2. the AK's own attestation says purposes == {ATTEST_KEY} and origin == GENERATED;
  3. k1 and k2 are signed by the AK, were GENERATED in the AK's security level, and carry
     the challenges the app used.
If all hold, k1 and k2 were generated in the KeyMint instance that holds the AK.

It then replays the forgery the probe prepared (Bob's key in an attestation certificate
re-signed by an ordinary key of Alice's device) against a verifier that skips check 2 and
against the full one. Given several result files, it also checks whether the AK persisted
across runs.

Usage: verify_attestkey.py RESULT.json [RESULT2.json ...]
"""
import base64
import hashlib
import json
import statistics
import sys
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ObjectIdentifier

KEY_DESCRIPTION = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
ROOTS_URL = "https://android.googleapis.com/attestation/root"
ROOTS_CACHE = Path(__file__).with_name("google_roots.json")
ECDSA_SHA256 = bytes.fromhex("300a06082a8648ce3d040302")

SECURITY_LEVEL = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}
PURPOSE = {0: "ENCRYPT", 1: "DECRYPT", 2: "SIGN", 3: "VERIFY", 5: "WRAP_KEY", 6: "AGREE_KEY", 7: "ATTEST_KEY"}
ORIGIN = {0: "GENERATED", 1: "DERIVED", 2: "IMPORTED", 3: "RESERVED", 4: "SECURELY_IMPORTED"}
VERIFIED_BOOT = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}
ATTEST_KEY, GENERATED = 7, 0
TAG_PURPOSE, TAG_ORIGIN, TAG_ROOT_OF_TRUST = 1, 702, 704


# --- minimal DER -------------------------------------------------------------------------

def tlv(buf, i=0):
    """One DER TLV at buf[i]: (tag number, value, next index); high tag numbers supported."""
    first = buf[i]
    i += 1
    number = first & 0x1F
    if number == 0x1F:
        number = 0
        while True:
            b = buf[i]
            i += 1
            number = (number << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    length = buf[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    return number, buf[i:i + length], i + length


def items(buf):
    out, i = [], 0
    while i < len(buf):
        number, value, i = tlv(buf, i)
        out.append((number, value))
    return out


def integer(value):
    return int.from_bytes(value, "big", signed=True)


def der(tag, content):
    n = len(content)
    if n < 0x80:
        head = bytes([n])
    else:
        size = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(size)]) + size
    return bytes([tag]) + head + content


# --- KeyMint attestation extension -------------------------------------------------------

def key_description(cert):
    """The KeyDescription extension, reduced to what the co-residency check needs."""
    try:
        raw = cert.extensions.get_extension_for_oid(KEY_DESCRIPTION).value.value
    except x509.ExtensionNotFound:
        return None
    _, seq, _ = tlv(raw)
    fields = items(seq)
    software, hardware = authorizations(fields[6][1]), authorizations(fields[7][1])
    return {
        "attestation_version": integer(fields[0][1]),
        "keymint_version": integer(fields[2][1]),
        "keymint_security_level": integer(fields[3][1]),
        "challenge": fields[4][1],
        "purposes": purposes(hardware),
        "origin": integer(hardware[TAG_ORIGIN]) if TAG_ORIGIN in hardware else None,
        "root_of_trust": root_of_trust(hardware.get(TAG_ROOT_OF_TRUST)),
    }


def authorizations(seq):
    """AuthorizationList: EXPLICIT context tags -> the inner value."""
    return {number: tlv(inner)[1] for number, inner in items(seq)}


def purposes(auth):
    if TAG_PURPOSE not in auth:
        return None
    return sorted(integer(v) for _, v in items(auth[TAG_PURPOSE]))


def root_of_trust(value):
    if value is None:
        return None
    f = items(value)
    return {
        "verified_boot_key": f[0][1].hex(),
        "device_locked": f[1][1] != b"\x00",
        "verified_boot_state": VERIFIED_BOOT.get(integer(f[2][1]), integer(f[2][1])),
        "verified_boot_hash": f[3][1].hex() if len(f) > 3 else None,
    }


# --- certificates ------------------------------------------------------------------------

def b64d(s):
    return base64.b64decode(s)


def certs(chain):
    return [x509.load_der_x509_certificate(b64d(c)) for c in chain]


def spki(cert):
    return cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)


def fingerprint(cert):
    return hashlib.sha256(spki(cert)).hexdigest()[:16]


def signed_by(cert, issuer_key):
    """True when cert's signature verifies under issuer_key (names are not compared)."""
    try:
        if isinstance(issuer_key, ec.EllipticCurvePublicKey):
            issuer_key.verify(cert.signature, cert.tbs_certificate_bytes,
                              ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(issuer_key, rsa.RSAPublicKey):
            issuer_key.verify(cert.signature, cert.tbs_certificate_bytes,
                              padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(issuer_key, ed25519.Ed25519PublicKey):
            issuer_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False
        return True
    except Exception:
        return False


def chain_to_google(chain, roots):
    """Each certificate is signed by the next, and the top one is or is signed by a Google root."""
    for child, parent in zip(chain, chain[1:]):
        if not signed_by(child, parent.public_key()):
            return False, f"breaks at {child.subject.rfc4514_string()}"
    top = chain[-1]
    if spki(top) in {spki(r) for r in roots} or any(signed_by(top, r.public_key()) for r in roots):
        return True, "ends at a Google attestation root"
    return False, "does not end at a Google attestation root"


def load_roots():
    try:
        with urllib.request.urlopen(ROOTS_URL, timeout=20) as r:
            pems = json.load(r)
        ROOTS_CACHE.write_text(json.dumps(pems, indent=1))
    except Exception as e:
        if not ROOTS_CACHE.exists():
            sys.exit(f"cannot fetch the Google roots ({e}) and there is no cache at {ROOTS_CACHE}")
        pems = json.loads(ROOTS_CACHE.read_text())
    return [x509.load_pem_x509_certificate(p.encode()) for p in pems]


def label(values, table):
    return "{" + ", ".join(table.get(v, str(v)) for v in values or []) + "}"


# --- checks ------------------------------------------------------------------------------

class Report:
    def __init__(self):
        self.failures = 0

    def check(self, ok, what):
        print(f"  [{'PASS' if ok else 'FAIL'}] {what}")
        if not ok:
            self.failures += 1
        return ok

    @staticmethod
    def note(what):
        print(f"  [ .. ] {what}")


def verify_pair(name, level, roots, report):
    """Checks 1-3. Returns the AK certificate when the AK itself could be read."""
    print(f"\n== {name}: co-residency of k1 and k2")
    ak_info = level.get("ak", {})
    if "error" in ak_info:
        report.check(False, f"attest key generation: {ak_info['error']}")
        return None
    ak_chain = certs(ak_info["chain"])
    ak = ak_chain[0]
    ok, why = chain_to_google(ak_chain, roots)
    report.check(ok, f"AK chain ({len(ak_chain)} certificates) {why}")
    akd = key_description(ak)
    if not report.check(akd is not None, "AK certificate carries a KeyMint attestation"):
        return ak
    report.check(akd["purposes"] == [ATTEST_KEY],
                 f"AK purposes = {label(akd['purposes'], PURPOSE)} (must be exactly ATTEST_KEY)")
    report.check(akd["origin"] == GENERATED, f"AK origin = {ORIGIN.get(akd['origin'], akd['origin'])}")
    if "challenge" in ak_info:
        report.check(akd["challenge"] == b64d(ak_info["challenge"]), "AK attestation carries the app's challenge")
    sec = akd["keymint_security_level"]
    report.note(f"AK lives in {SECURITY_LEVEL.get(sec, sec)} (KeyMint {akd['keymint_version']}, "
                f"attestation v{akd['attestation_version']}); reused from an earlier run: {ak_info.get('reused')}")

    for k in ("k1", "k2"):
        info = level.get(k, {})
        if "error" in info:
            report.check(False, f"{k} generation: {info['error']}")
            continue
        chain = certs(info["chain"])
        leaf, d = chain[0], key_description(chain[0])
        report.check(leaf.issuer == ak.subject and signed_by(leaf, ak.public_key()),
                     f"{k} attestation is signed by the AK (chain length {len(chain)})")
        if not report.check(d is not None, f"{k} certificate carries a KeyMint attestation"):
            continue
        report.check(d["origin"] == GENERATED, f"{k} origin = {ORIGIN.get(d['origin'], d['origin'])}")
        report.check(d["keymint_security_level"] == sec,
                     f"{k} security level = {SECURITY_LEVEL.get(d['keymint_security_level'])}")
        report.check(d["challenge"] == b64d(info["challenge"]), f"{k} attestation carries the app's challenge")
    return ak


def replay_forgery(level, roots, report):
    f = level.get("forgery")
    print("   forgery: Bob's key in an attestation re-signed by an ordinary key of Alice's device")
    if not f or "error" in f:
        report.note(f"not available: {f.get('error') if f else 'no forgery recorded'}")
        return
    tbs, sig = b64d(f["tbs"]), b64d(f["signature"])
    forged = x509.load_der_x509_certificate(der(0x30, tbs + ECDSA_SHA256 + der(0x03, b"\x00" + sig)))
    signer_chain = certs(f["signer_chain"])
    signer, sd, fd = signer_chain[0], key_description(signer_chain[0]), key_description(forged)
    chain_ok = chain_to_google(signer_chain, roots)[0]

    report.note(f"forged certificate carries Bob's key: {spki(forged) == b64d(f['bob_spki'])}; "
                f"its extension still claims origin {ORIGIN.get(fd and fd['origin'])}")
    report.note(f"signer: genuine Google chain {chain_ok}, purposes {label(sd and sd['purposes'], PURPOSE)}, "
                f"subject equal to the AK's {forged.issuer == signer.subject}")
    naive = (chain_ok and forged.issuer == signer.subject and signed_by(forged, signer.public_key())
             and fd is not None and fd["origin"] == GENERATED)
    full = naive and sd is not None and sd["purposes"] == [ATTEST_KEY]
    report.note(f"verifier WITHOUT the purpose check: {'ACCEPTS' if naive else 'rejects'} the forgery")
    report.check(not full, "verifier WITH the purpose check rejects the forgery")


def report_level_extras(level, report):
    attempt = level.get("ak_sign_attempt", "")
    report.check(attempt.startswith("refused"), f"AK refuses to sign arbitrary data ({attempt[:110]})")
    t = level.get("timing", {})
    if t:
        def med(key):
            values = [v for v in t.get(key, []) if v >= 0]
            return f"{statistics.median(values):.0f}" if values else "n/a"
        report.note(f"median ms: AK generation {med('attest_key_gen_ms')}, key + system attestation "
                    f"{med('system_attested_key_gen_ms')}, key + AK attestation {med('ak_attested_key_gen_ms')}")


def privacy_notes(ak_chain_b64):
    chain = certs(ak_chain_b64)
    ak, d = chain[0], key_description(chain[0])
    if len(chain) > 1:
        print(f"   privacy: AK certificate issued by {chain[1].subject.rfc4514_string()} "
              f"(key {fingerprint(chain[1])}); whoever sees this chain sees that issuer")
    if d and d["root_of_trust"]:
        r = d["root_of_trust"]
        print(f"   privacy: RootOfTrust boot key {r['verified_boot_key'][:16]}…, boot hash "
              f"{(r['verified_boot_hash'] or '')[:16]}…, locked {r['device_locked']}, {r['verified_boot_state']} "
              f"(same for every device of this model and build)")


def main(paths):
    roots = load_roots()
    report = Report()
    seen_aks = {}
    for path in paths:
        result = json.loads(Path(path).read_text())
        dev = result["device"]
        print(f"\n##### {path}\n{dev['manufacturer']} {dev['model']}, Android {dev['release']} "
              f"(API {dev['sdk']}, patch {dev['security_patch']}); StrongBox {dev['strongbox']}, "
              f"app attest keys {dev['app_attest_keys']}")
        for name, level in result["levels"].items():
            before = report.failures
            ak = verify_pair(name, level, roots, report)
            replay_forgery(level, roots, report)
            report_level_extras(level, report)
            if ak is not None:
                privacy_notes(level["ak"]["chain"])
                seen_aks.setdefault(name, []).append((path, fingerprint(ak)))
            print(f"   => {name}: " + ("k1 and k2 are proven co-resident with the AK"
                                       if report.failures == before else "co-residency NOT established"))
        for what, a in result.get("cross_level", {}).items():
            report.check(not a["outcome"].startswith("ACCEPTED"),
                         f"cross-instance {what.replace('_', ' ')}: {a['outcome'][:110]}")

    if len(paths) > 1:
        print("\n== AK persistence across runs")
        for name, runs in seen_aks.items():
            same = len({fp for _, fp in runs}) == 1
            report.note(f"{name}: AK {'identical' if same else 'DIFFERENT'} across {len(runs)} runs "
                        f"({', '.join(fp for _, fp in runs)})")

    print(f"\n{'ALL CHECKS PASSED' if report.failures == 0 else f'{report.failures} CHECK(S) FAILED'}")
    return 0 if report.failures == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
