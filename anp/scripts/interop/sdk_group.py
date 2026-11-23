"""P6 (group E2EE) with the official Python SDK's proof helpers.

  sdk_group.py verify     the SDK verifies the binding and the origin proofs this project made (mine.group.json)
  sdk_group.py sign       the SDK makes an origin proof, for this project to verify (sdk.group.json)

The SDK's `did_wba_binding` helper is the older five-field form (no device_id) and has no P6 eligibility check, so what it can say about a
v2 binding is: the key is authorised for assertionMethod, the window holds, the leaf key and credential identity agree, and the object
proof verifies. Origin proofs go through the SDK's own RFC 9421 origin-proof functions, including the proof preserved on a delivery.
"""
import json, os, sys
from datetime import datetime
OUT = os.environ.get("INTEROP_OUT", "/mnt/c/cbt-anp/interop")
sys.path.insert(0, os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs")))
from cryptography.hazmat.primitives import serialization
from anp.authentication.did_wba import create_did_wba_document
from anp.proof.did_wba_binding import verify_did_wba_binding
from anp.proof.rfc9421_origin import (generate_rfc9421_origin_proof, verify_rfc9421_origin_proof, Rfc9421OriginProofGenerationOptions,
                                       Rfc9421OriginProofVerificationOptions, Rfc9421OriginProofError)
from anp.proof.im import ImProofError

mode = sys.argv[1]
ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)[:300]))

def refuses(fn):
    try:
        fn()
        return False
    except (ImProofError, Rfc9421OriginProofError, ValueError, KeyError):
        return True

if mode == "verify":
    v = json.load(open(f"{OUT}/mine.group.json"))
    now = datetime.fromisoformat(v["now"].replace("Z", "+00:00"))
    b, doc = v["binding"], v["binding_doc"]
    check("the SDK verifies the device binding this project signed (assertionMethod, window, leaf key, credential identity, object proof)",
          verify_did_wba_binding(b, doc, now=now, expected_leaf_signature_key_b64u=v["leaf_key"], expected_credential_identity=v["binding_did"]))
    tampered = dict(b, expires_at="2030-01-01T00:00:00Z")
    check("...and refuses a binding whose window was changed (the proof covers it)", not verify_did_wba_binding(tampered, doc, now=now))
    check("...and one whose leaf key is not the MLS leaf's", not verify_did_wba_binding(b, doc, now=now, expected_leaf_signature_key_b64u="AAAA"))
    opts = Rfc9421OriginProofVerificationOptions(expected_signer_did=v["signer_did"])
    r = verify_rfc9421_origin_proof(v["proof"], v["method"], v["meta"], v["body"], did_document=v["signer_doc"], options=opts)
    check(f"the SDK verifies the origin proof this project made on a group.e2ee.send (keyid {r.parsed_signature_input.keyid[-20:]})", r is not None)
    check("...and refuses it when the body changed", refuses(lambda: verify_rfc9421_origin_proof(v["proof"], v["method"], dict(v["body"], epoch="99") and v["meta"], dict(v["body"], epoch="99"), did_document=v["signer_doc"], options=opts)))
    check("...and when the expected signer is someone else", refuses(lambda: verify_rfc9421_origin_proof(v["proof"], v["method"], v["meta"], v["body"], did_document=v["signer_doc"], options=Rfc9421OriginProofVerificationOptions(expected_signer_did="did:wba:other.example:agents:x"))))
    inc = v["incoming"]
    rec = inc["reconstructed"]
    r2 = verify_rfc9421_origin_proof(inc["auth"]["origin_proof"], rec["method"], rec["meta"], rec["body"], did_document=v["signer_doc"], options=opts)
    check("the proof this project preserved on a group.incoming delivery verifies against the request it reconstructed (the SDK's own verifier)", r2 is not None)
    sys.exit(0 if ok else 1)

if mode == "sign":
    f = json.load(open(f"{OUT}/mine.group.json"))
    doc, keys = create_did_wba_document(hostname="sdk-owner.example", path_segments=["agents", "sdkalice"], did_profile="e1")
    priv = serialization.load_pem_private_key(keys["key-1"][0], password=None)
    meta = dict(f["meta"], sender_did=doc["id"])
    keyid = doc["authentication"][0] if isinstance(doc["authentication"][0], str) else doc["authentication"][0]["id"]
    proof = generate_rfc9421_origin_proof(f["method"], meta, f["body"], priv, keyid, options=Rfc9421OriginProofGenerationOptions(created=1784419200, nonce="sdk-nonce"))
    json.dump({"signer_doc": doc, "signer_did": doc["id"], "method": f["method"], "meta": meta, "body": f["body"], "proof": proof}, open(f"{OUT}/sdk.group.json", "w"), indent=1)
    print("the SDK made an origin proof as", doc["id"][:50] + "...")