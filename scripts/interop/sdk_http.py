"""ANP-02 both ways with the official SDK.
  verify  : the SDK verifies a request signed by this project's Rust code
  sign    : the SDK signs a request (with a DID document it created) for the Rust verifier to check
"""
import json, sys, time
import os
OUT = os.environ.get("INTEROP_OUT", "/mnt/c/cbt-anp/interop")
LIBS = os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs"))
sys.path.insert(0, LIBS)
from cryptography.hazmat.primitives import serialization
from anp.authentication.did_wba import create_did_wba_document
from anp.authentication.http_signatures import generate_http_signature_headers, verify_http_message_signature


mode = sys.argv[1]

if mode == "verify":
    fx = json.load(open(f"{OUT}/mine.http.json"))
    ok, msg, meta = verify_http_message_signature(fx["did_document"], fx["method"], fx["url"], fx["headers"], fx["body"])
    print(("PASS  " if ok else "FAIL  ") + "SDK verifies a request signed by my Rust code:", msg, {k: meta.get(k) for k in ("nonce", "components")})
    ok2, msg2, _ = verify_http_message_signature(fx["did_document"], fx["method"], fx["url"], fx["headers"], '{"jsonrpc":"2.0","method":"Other"}')
    print(("PASS  " if not ok2 else "FAIL  ") + "...and refuses it with a changed body:", msg2)
    sys.exit(0 if ok and not ok2 else 1)

if mode == "sign":
    doc, keys = create_did_wba_document(hostname="sdk.example.com", path_segments=["agents", "sdkbot"], did_profile="e1")
    priv = serialization.load_pem_private_key(keys["key-1"][0], password=None)
    def sign_callback(content: bytes, fragment: str) -> bytes:
        return priv.sign(content)
    url = "https://node.example.com:8800/rpc?x=1"
    body = '{"jsonrpc":"2.0","method":"ListTasks"}'
    headers = generate_http_signature_headers(doc, url, "POST", sign_callback, body=body)
    json.dump({"did_document": doc, "method": "POST", "url": url, "body": body, "headers": headers}, open(f"{OUT}/sdk.http.json", "w"), indent=1)
    print("SDK signed a request as", doc["id"][:60] + "...")
