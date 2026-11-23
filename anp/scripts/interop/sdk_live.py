"""The official ANP SDK's client against a running node that requires ANP-02 signed requests.

  prep : create two e1 DIDs with the SDK (one accepted by the node, one not) and save them
  run  : call the node over HTTP
"""
import json, sys, urllib.request, urllib.error
import os
OUT = os.environ.get("INTEROP_OUT", "/mnt/c/cbt-anp/interop")
LIBS = os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs"))
sys.path.insert(0, LIBS)
from cryptography.hazmat.primitives import serialization
from anp.authentication.did_wba import create_did_wba_document
from anp.authentication.http_signatures import generate_http_signature_headers


BASE = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:18797"

def make(name):
    doc, keys = create_did_wba_document(hostname=f"{name}.example.com", path_segments=["agents", name], did_profile="e1")
    json.dump(doc, open(f"{OUT}/{name}.did.json", "w"), indent=1)
    open(f"{OUT}/{name}.key.pem", "wb").write(keys["key-1"][0])

def signer(name):
    doc = json.load(open(f"{OUT}/{name}.did.json"))
    priv = serialization.load_pem_private_key(open(f"{OUT}/{name}.key.pem", "rb").read(), password=None)
    return doc, (lambda content, fragment: priv.sign(content))

def call(method, path, body=None, headers=None):
    req = urllib.request.Request(BASE + path, data=body.encode() if body is not None else None, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)

def signed(name, method, path, body=None):
    doc, cb = signer(name)
    h = generate_http_signature_headers(doc, BASE + path, method, cb, body=body)
    if body is not None:
        h["Content-Type"] = "application/json"
    return h

if sys.argv[1] == "prep":
    make("sdkclient"); make("stranger")
    print("created", json.load(open(f"{OUT}/sdkclient.did.json"))["id"])
    sys.exit(0)

ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)[:300]))

rpc = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": {"messageId": "m-1", "role": "ROLE_USER", "parts": [{"text": "hello from the official SDK"}]}}})

s, b, h = call("POST", "/", rpc, {"Content-Type": "application/json"})
check("an unsigned JSON-RPC call is refused with 401", s == 401, (s, b))
check("...and the challenge names the scheme (WWW-Authenticate: DIDWba, Accept-Signature)", "DIDWba" in h.get("WWW-Authenticate", "") and "Accept-Signature" in h or "accept-signature" in {k.lower() for k in h}, h)

hs = signed("sdkclient", "POST", "/", rpc)
s, b, _ = call("POST", "/", rpc, hs)
r = json.loads(b) if s == 200 else {}
check("a call signed by the SDK is accepted and answered (SendMessage -> a completed task)", s == 200 and r.get("result", {}).get("task", {}).get("status", {}).get("state") == "TASK_STATE_COMPLETED", (s, b))
s2, b2, _ = call("POST", "/", rpc, hs)
check("the same signed request sent again (a replay) is refused", s2 == 401, (s2, b2))

hs = signed("sdkclient", "POST", "/", rpc)
s, b, _ = call("POST", "/", rpc.replace("hello", "HELLO"), hs)
check("a signed request with its body changed in transit is refused", s == 401, (s, b))

hs = signed("sdkclient", "GET", "/agents")
s, b, _ = call("GET", "/other-path", None, hs)
check("a signature made for one path does not work on another", s == 401, (s, b))

hs = signed("sdkclient", "GET", "/agents")
s, b, _ = call("GET", "/agents", None, hs)
check("a signed GET of the mesh directory works", s == 200 and isinstance(json.loads(b), list), (s, b))

hs = signed("stranger", "GET", "/agents")
s, b, _ = call("GET", "/agents", None, hs)
check("a request signed by a valid DID the node was not told to accept is refused", s == 401, (s, b))

s, b, _ = call("GET", "/.well-known/agent-descriptions")
check("the discovery listing stays public (no signature needed)", s == 200 and "CollectionPage" in b, (s, b))
s, b, _ = call("GET", "/.well-known/agent-card.json")
check("the agent card stays public", s == 200 and "name" in b, (s, b))

sys.exit(0 if ok else 1)
