"""The official SDK's client using the older scheme (`Authorization: DIDWba` header, then the Bearer token) against a node.

  sdk_legacy_live.py refused BASE   the node was not asked to accept the older scheme: the header must be refused
  sdk_legacy_live.py run BASE       the node accepts it
Needs the DIDs that sdk_live.py prep makes (sdkclient: accepted by the node; stranger: not).
"""
import json, os, sys, urllib.request, urllib.error
OUT = os.environ.get("INTEROP_OUT", "/mnt/c/cbt-anp/interop")
sys.path.insert(0, os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs")))
from urllib.parse import urlparse
from cryptography.hazmat.primitives import serialization
from anp.authentication import DIDWbaAuthHeader
from anp.authentication.did_wba import generate_auth_header

mode, BASE = sys.argv[1], sys.argv[2]
DOMAIN = urlparse(BASE).hostname

def client(name):
    return DIDWbaAuthHeader(f"{OUT}/{name}.did.json", f"{OUT}/{name}.key.pem", auth_mode="legacy_didwba")

def call(method, path, body=None, headers=None):
    req = urllib.request.Request(BASE + path, data=body.encode() if body is not None else None, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)

ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)[:300]))

if mode == "refused":
    s, b, _ = call("GET", "/agents", None, client("sdkclient").get_auth_header(BASE + "/agents"))
    check("a node not asked to accept the older scheme refuses a DIDWba header", s == 401, (s, b))
    sys.exit(0 if ok else 1)

c = client("sdkclient")
h = c.get_auth_header(BASE + "/agents")
check("the SDK builds a legacy DIDWba header", h["Authorization"].startswith("DIDWba "), h)
s, b, rh = call("GET", "/agents", None, h)
check("the header is accepted (GET of the mesh directory)", s == 200 and isinstance(json.loads(b), list), (s, b))
lower = {k.lower(): v for k, v in rh.items()}
check("the node answers with an Authentication-Info token", "access_token=" in lower.get("authentication-info", "") and "expires_in=3600" in lower.get("authentication-info", ""), rh)
token = c.update_token(BASE + "/agents", rh)
check("the SDK stores that token", bool(token))

h2 = c.get_auth_header(BASE + "/agents")
check("the SDK now sends the Bearer token", h2["Authorization"] == f"Bearer {token}", h2)
rpc = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": {"messageId": "m-9", "role": "ROLE_USER", "parts": [{"text": "hello over the older scheme"}]}}})
s, b, _ = call("POST", "/", rpc, {**h2, "Content-Type": "application/json"})
r = json.loads(b) if s == 200 else {}
check("a JSON-RPC call with the Bearer token is answered", s == 200 and r.get("result", {}).get("task", {}).get("status", {}).get("state") == "TASK_STATE_COMPLETED", (s, b))
s, b, _ = call("GET", "/agents", None, h2)
check("the token can be used again (it is not one-shot)", s == 200, (s, b))

s, b, _ = call("GET", "/agents", None, h)
check("the same DIDWba header sent again (a replay) is refused", s == 401, (s, b))

bad = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
s, b, _ = call("GET", "/agents", None, {"Authorization": f"Bearer {bad}"})
check("a Bearer token with a damaged signature is refused", s == 401, (s, b))
s, b, _ = call("GET", "/agents", None, {"Authorization": "Bearer not.a.token"})
check("so is one that is not a token", s == 401, (s, b))

# a header made for another server's domain
doc = json.load(open(f"{OUT}/sdkclient.did.json"))
priv = serialization.load_pem_private_key(open(f"{OUT}/sdkclient.key.pem", "rb").read(), password=None)
sign = lambda content, frag: priv.sign(content)
other = generate_auth_header(doc, "other.example.com", sign)
s, b, _ = call("GET", "/agents", None, {"Authorization": other})
check("a header signed for another domain is refused", s == 401, (s, b))
old = generate_auth_header(doc, DOMAIN, sign, timestamp="2020-01-01T00:00:00Z")
s, b, _ = call("GET", "/agents", None, {"Authorization": old})
check("a header with an old timestamp is refused", s == 401, (s, b))
fresh = generate_auth_header(doc, DOMAIN, sign)
s, b, _ = call("GET", "/agents", None, {"Authorization": fresh.replace('nonce="', 'nonce="x')})
check("a header whose nonce was changed after signing is refused", s == 401, (s, b))
s, b, _ = call("GET", "/agents", None, client("stranger").get_auth_header(BASE + "/agents"))
check("a valid DID the node was not told to accept is refused", s == 401, (s, b))
s, b, _ = call("GET", "/.well-known/agent-descriptions")
check("the discovery listing stays public", s == 200, (s, b))
sys.exit(0 if ok else 1)