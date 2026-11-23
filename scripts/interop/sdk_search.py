"""The official SDK's readers and verifier against the search agent, with a node behind a TLS proxy as what it indexes.

  sdk_search.py SEARCH_HTTP_BASE NODE_HTTP_BASE

SEARCH_HTTP_BASE and NODE_HTTP_BASE are how this script reaches them; inside, the node calls itself https://localhost:8443 and
the search agent https://localhost:8444 (TLS proxies with a test CA in front of both).
"""
import json, os, sys, urllib.request, urllib.error
LIBS = os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs"))
sys.path.insert(0, LIBS)
import base58
from anp.anp_crawler.anp_parser import ANPDocumentParser
from anp.anp_crawler.anp_interface import ANPInterfaceConverter
from anp.proof.proof import verify_w3c_proof
from cryptography.hazmat.primitives.asymmetric import ed25519

SEARCH, NODE = sys.argv[1].rstrip("/"), sys.argv[2].rstrip("/")
NODE_DOMAIN, SEARCH_DOMAIN = "localhost:8443", "localhost:8444"

def get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read().decode())

def rpc(method, **params):
    req = urllib.request.Request(SEARCH + "/", data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())

def sdk_verifies(ad, did_doc, domain):
    vm_id = ad["proof"]["verificationMethod"]
    vm = next(m for m in did_doc["verificationMethod"] if m["id"] == vm_id or m["id"].endswith(vm_id.split("#")[-1]))
    raw = base58.b58decode(vm["publicKeyMultibase"][1:])[2:]  # multicodec prefix of an Ed25519 key
    return verify_w3c_proof(ad, ed25519.Ed25519PublicKey.from_public_bytes(raw), expected_purpose="assertionMethod", expected_domain=domain)

ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)[:300]))

# the search agent's own documents, read by the SDK
ad = get(SEARCH + "/agents/search/ad.json")
did_path = "/" + "/".join(ad["did"].split(":")[3:]) + "/did.json"
did_doc = get(SEARCH + did_path)
check("the SDK verifies the search agent's signed description against its DID document", sdk_verifies(ad, did_doc, SEARCH_DOMAIN))
parser = ANPDocumentParser()
orpc_url = next(i["url"] for i in parser.parse_document(json.dumps(ad), "application/json", ad["url"])["interfaces"] if i["protocol"] == "openrpc")
doc = get(SEARCH + "/agents/search/openrpc.json")
methods = parser.parse_document(json.dumps(doc), "application/json", orpc_url)["interfaces"]
names = [m["method_name"] for m in methods]
check(f"the crawler's parser finds the OpenRPC interface and its methods ({', '.join(names)})", names == ["register", "crawl", "refresh", "search", "search_handle", "list"], names)
conv = ANPInterfaceConverter()
tools = [conv.convert_to_openai_tools(m) for m in methods]
check("the SDK's converter makes a model tool of each", all(t and t["function"]["name"] for t in tools), tools)
search_tool = next(t for t in tools if t["function"]["name"] == "search")
check("the search tool takes `query` (required)", "query" in search_tool["function"]["parameters"]["properties"] and "query" in search_tool["function"]["parameters"].get("required", []), search_tool)

# active discovery of a domain, then search
r = rpc("crawl", domain=NODE_DOMAIN)
res = r.get("result", {})
check("crawling the node's domain lists its description and registers it", res.get("listed") == 1 and res.get("registered") == 1, r)
r = rpc("search", query="hotel")
hits = r.get("result", {}).get("results", [])
check("a search finds it", len(hits) == 1 and hits[0]["name"] == "hotel", r)
hit = hits[0]
node_ad = get(NODE + "/agents/hotel/ad.json")
node_did = get(NODE + "/" + "/".join(node_ad["did"].split(":")[3:]) + "/did.json")
check("the SDK verifies the description that was indexed, and it is the DID the search agent reports", sdk_verifies(node_ad, node_did, NODE_DOMAIN) and node_ad["did"] == hit["did"], (hit["did"], node_ad["did"]))
check("the entry carries the protocols of the description (A2A, openrpc)", set(hit["protocols"]) >= {"A2A", "openrpc"}, hit["protocols"])
r = rpc("search", query="hotel", protocol="openrpc")
check("a protocol filter keeps it", len(r["result"]["results"]) == 1, r)
r = rpc("search", query="hotel", protocol="MCP")
check("and another protocol drops it", r["result"]["results"] == [], r)
r = rpc("search", query="zebra")
check("a query nothing matches finds nothing", r["result"]["results"] == [], r)

# what it must refuse
r = rpc("register", url=f"https://{NODE_DOMAIN}/agents/ghost/ad.json")
check("a description that is not there is refused", r.get("error", {}).get("code") == -32010, r)
r = rpc("register", url=f"http://{NODE_DOMAIN}/agents/hotel/ad.json")
check("plain http is refused", r.get("error", {}).get("code") == -32010 and "https" in r["error"]["message"], r)
r = rpc("register", url="https://127.0.0.1:8443/agents/hotel/ad.json")
check("the same description fetched from another address is refused (it names a different URL and domain)", r.get("error", {}).get("code") == -32010, r)
r = rpc("register", url=f"https://{NODE_DOMAIN}/agents/hotel/ad.json")
check("registering again is fine (it is an update)", r.get("result", {}).get("name") == "hotel", r)
r = rpc("register", url=f"https://{SEARCH_DOMAIN}/agents/search/ad.json")
check("the search agent can register itself (so it can be found by another one)", r.get("result", {}).get("name") == "search", r)
r = rpc("list")
check("the list holds both", r["result"]["total"] == 2, r)
r = rpc("refresh", url=f"https://{NODE_DOMAIN}/agents/ghost/ad.json")
check("refreshing something that was never registered is an error", "error" in r, r)
sys.exit(0 if ok else 1)