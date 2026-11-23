"""Have the official ANP SDK check the P5 v2 objects this project produced (fixture from `dump_interop_fixture`)."""
import json, sys
import os
OUT = os.environ.get("INTEROP_OUT", "/mnt/c/cbt-anp/interop")
LIBS = os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs"))
from datetime import datetime, timezone
sys.path.insert(0, LIBS)
from anp.direct_e2ee.v2_models import V2PrekeyBundle, V2DirectMetadata, V2DirectInitBody, V2ApplicationPlaintext
from anp.direct_e2ee.v2_bundle import verify_prekey_bundle_v2
from anp.direct_e2ee.v2_aad import build_init_aad_v2, canonical_application_plaintext_v2

fx = json.load(open(f"{OUT}/mine.p5.json"))
ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)))

rcpt = fx["recipient"]
now = datetime.fromisoformat(fx["now"].replace("Z", "+00:00"))

# 1. the SDK verifies my signed prekey bundle against my DID document (manifest eligibility, signing key, proof, expiry)
try:
    verify_prekey_bundle_v2(V2PrekeyBundle.from_dict(rcpt["bundle"]), rcpt["did_document"], now)
    check("SDK accepts my prekey bundle against my DID document and device manifest", True)
except Exception as e:
    check("SDK accepts my prekey bundle against my DID document and device manifest", False, repr(e))

# 2. the SDK's init AAD for my message is byte-for-byte mine
meta = V2DirectMetadata.from_dict({
    "profile": "anp.direct.e2ee.v2", "security_profile": "direct-e2ee",
    "sender_did": fx["sender"]["did"], "sender_device_id": fx["sender"]["device_id"],
    "target": {"kind": "agent", "did": rcpt["did_document"]["id"]},
    "recipient_device_id": rcpt["device_id"],
    "operation_id": fx["message_id"], "message_id": fx["message_id"],
    "content_type": "application/anp-direct-init+json",
})
body = V2DirectInitBody.from_dict(fx["init_body"])
try:
    ad = build_init_aad_v2(meta, body).decode()
    check("SDK builds the same init AAD as my code", ad == fx["expected_ad_init"], f"\n sdk : {ad}\n mine: {fx['expected_ad_init']}")
except Exception as e:
    check("SDK builds the same init AAD as my code", False, repr(e))

# 3. the SDK accepts my init body's shape
try:
    body.validate()
    check("SDK accepts the shape of my init body", True)
except Exception as e:
    check("SDK accepts the shape of my init body", False, repr(e))

# 4. canonical application plaintext (numbers included) is byte-for-byte mine
try:
    ap = V2ApplicationPlaintext.from_dict(fx["application_plaintext"])
    plain = canonical_application_plaintext_v2(ap).decode()
    check("SDK canonicalises my application plaintext identically (RFC 8785 numbers too)", plain == fx["expected_application_plaintext_jcs"], f"\n sdk : {plain}\n mine: {fx['expected_application_plaintext_jcs']}")
except Exception as e:
    check("SDK canonicalises my application plaintext identically (RFC 8785 numbers too)", False, repr(e))

sys.exit(0 if ok else 1)
