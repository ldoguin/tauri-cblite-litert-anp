"""The official SDK's client against a node that was NOT given the caller's DID document, only a trusted domain.

  prep : make DIDs with the SDK: two on the trusted domain (one published, one not), one on another domain
  run  : call the node
"""
import json, os, sys, urllib.request, urllib.error
OUT = os.environ.get("INTEROP_OUT", "/mnt/c/cbt-anp/interop")
sys.path.insert(0, os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs")))
from cryptography.hazmat.primitives import serialization
from anp.authentication.did_wba import create_did_wba_document
from anp.authentication.http_signatures import generate_http_signature_headers

BASE = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:18797"

def make(name, port):
    doc, keys = create_did_wba_document(hostname="localhost", port=port, path_segments=["agents", name], did_profile="e1")
    json.dump(doc, open(f"{OUT}/{name}.did.json", "w"), indent=1)
    open(f"{OUT}/{name}.key.pem", "wb").write(keys["key-1"][0])

def signed(name, method, path, body=None):
    doc = json.load(open(f"{OUT}/{name}.did.json"))
    priv = serialization.load_pem_private_key(open(f"{OUT}/{name}.key.pem", "rb").read(), password=None)
    h = generate_http_signature_headers(doc, BASE + path, method, lambda content, fragment: priv.sign(content), body=body)
    if body is not None:
        h["Content-Type"] = "application/json"
    return h

def call(method, path, body=None, headers=None):
    req = urllib.request.Request(BASE + path, data=body.encode() if body is not None else None, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

if sys.argv[1] == "prep":
    make("webclient", 8443); make("ghost", 8443); make("elsewhere", 8444)
    print("created", json.load(open(f"{OUT}/webclient.did.json"))["id"])
    sys.exit(0)

ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)[:300]))

rpc = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": {"messageId": "m-2", "role": "ROLE_USER", "parts": [{"text": "hello, resolved over HTTPS"}]}}})
s, b = call("GET", "/agents", None, signed("ghost", "GET", "/agents"))
check("a DID on the trusted domain that publishes no document is refused", s == 401, (s, b))
s, b = call("GET", "/agents", None, signed("elsewhere", "GET", "/agents"))
check("a DID on a domain that is not trusted is refused", s == 401, (s, b))
s, b = call("POST", "/", rpc, signed("webclient", "POST", "/", rpc))
r = json.loads(b) if s == 200 else {}
check("a call from a DID that only its domain vouches for is accepted (document fetched over HTTPS)", s == 200 and r.get("result", {}).get("task", {}).get("status", {}).get("state") == "TASK_STATE_COMPLETED", (s, b))
h = signed("webclient", "POST", "/", rpc)
call("POST", "/", rpc, h)
s, b = call("POST", "/", rpc, h)
check("the same signed request again (a replay) is refused", s == 401, (s, b))
s, b = call("POST", "/", rpc.replace("hello", "HELLO"), signed("webclient", "POST", "/", rpc))
check("a body changed in transit is refused", s == 401, (s, b))
s, b = call("GET", "/agents", None, signed("webclient", "GET", "/agents"))
check("a signed GET works for it too", s == 200, (s, b))
sys.exit(0 if ok else 1)