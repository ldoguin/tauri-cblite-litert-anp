"""The official SDK's readers against a node's agent description and its OpenRPC interface.

  sdk_openrpc.py BASE NODE_NAME

* the SDK's own header generator (fastanp ADGenerator) is compared with the header of our description;
* the crawler's parser and converter (anp_crawler) and the openanp client's parser turn what the node serves into tools;
* a tool call built from the OpenRPC document goes to the node and is answered.
fastapi is not installed, so the two SDK packages that import it at the top are loaded without their __init__ (the modules
used import nothing of fastapi).
"""
import asyncio, json, os, sys, types, urllib.request, urllib.error
from urllib.parse import urlparse
LIBS = os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs"))
sys.path.insert(0, LIBS)
import anp
from anp.anp_crawler.anp_parser import ANPDocumentParser
from anp.anp_crawler.anp_interface import ANPInterfaceConverter

def stub(name, sub):
    m = types.ModuleType(name)
    m.__path__ = [os.path.join(os.path.dirname(anp.__file__), *sub)]
    sys.modules[name] = m
stub("anp.fastanp", ["fastanp"]); stub("anp.openanp", ["openanp"]); stub("anp.openanp.client", ["openanp", "client"])
from anp.fastanp.ad_generator import ADGenerator
from anp.openanp.client.openrpc import parse_openrpc, parse_agent_document, convert_to_openai_tool

BASE, NAME = sys.argv[1].rstrip("/"), sys.argv[2]

def get(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        return r.status, json.loads(r.read().decode()), dict(r.headers)

def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())

def local(url):  # the documents name https://<did host>/...; the node is reached here
    return BASE + urlparse(url).path

ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)[:300]))

s, ad, _ = get(f"{BASE}/agents/{NAME}/ad.json")
check("the node serves its agent description", s == 200 and ad.get("type") == "AgentDescription", ad)

# our header against the SDK's own generator
gen = ADGenerator(name=ad["name"], description=ad.get("description") or "x", did=ad["did"], agent_domain="https://example.com").generate_common_header(ad_url=ad["url"])
missing = [k for k in gen if k not in ad]
check("every field of the SDK's header is in our description (" + ", ".join(sorted(gen)) + ")", not missing, missing)
same = [k for k in ("protocolType", "protocolVersion", "type", "securityDefinitions", "security") if gen[k] != ad.get(k)]
check("and the fixed ones (protocolType, protocolVersion, type, securityDefinitions, security) are identical", not same, {k: (gen[k], ad.get(k)) for k in same})
check("`created` has the SDK's second-precision UTC form", len(ad["created"]) == len(gen["created"]) and ad["created"].endswith("Z"), ad["created"])

# the crawler's parser reads the description
parser = ANPDocumentParser()
found = parser.parse_document(json.dumps(ad), "application/json", ad["url"])["interfaces"]
orpc = [i for i in found if i["protocol"] == "openrpc"]
check("the crawler's parser finds the A2A and the OpenRPC interface in the description", {i["protocol"] for i in found} >= {"A2A", "openrpc"}, found)
url = orpc[0]["url"]
s, doc, _ = get(local(url))
check("the OpenRPC document is served at the URL the description names", s == 200 and "openrpc" in doc, doc)

methods = parser.parse_document(json.dumps(doc), "application/json", url)["interfaces"]
names = [m["method_name"] for m in methods]
check(f"the crawler's parser reads the methods ({', '.join(names)})", names == ["SendMessage", "GetTask", "ListTasks", "CancelTask"], names)
conv = ANPInterfaceConverter()
tools = [conv.convert_to_openai_tools(m) for m in methods]
check("the crawler's converter turns every method into a model tool", all(t and t["function"]["name"] for t in tools), tools)
send = next(t for t in tools if t["function"]["name"] == "SendMessage")
props = send["function"]["parameters"]["properties"]
check("SendMessage's tool has its `message` parameter, with the $ref to Message resolved", "message" in props and "messageId" in json.dumps(props["message"]), props)

# the openanp client's parser
parsed = parse_openrpc(doc)
check("the openanp client's parse_openrpc accepts the document", [m["name"] for m in parsed] == names, parsed)
_, embedded = parse_agent_document(ad)
check("and parse_agent_document accepts the description (the OpenRPC is linked, not embedded)", embedded == [], embedded)
tool = convert_to_openai_tool(parsed[0])
check("convert_to_openai_tool builds a tool from it", tool["function"]["name"] == "SendMessage", tool)
rpc_url = parsed[0]["servers"][0]["url"]
check("the method's server URL is where the node's JSON-RPC lives", urlparse(rpc_url).path == "/", rpc_url)

# a call as a client would make it from the tool definition: by-name params
r = post(BASE + "/", {"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": {"messageId": "m-orpc", "role": "ROLE_USER", "parts": [{"text": "hello via OpenRPC"}]}}})
check("a call built from the document is answered (SendMessage -> a completed task)", r.get("result", {}).get("task", {}).get("status", {}).get("state") == "TASK_STATE_COMPLETED", r)
tid = r["result"]["task"]["id"]
r2 = post(BASE + "/", {"jsonrpc": "2.0", "id": 2, "method": "GetTask", "params": {"id": tid}})
check("GetTask by name returns the task", r2.get("result", {}).get("id") == tid, r2)
r3 = post(BASE + "/", {"jsonrpc": "2.0", "id": 3, "method": "ListTasks", "params": {"pageSize": 5}})
check("ListTasks by name returns a page", isinstance(r3.get("result", {}).get("tasks"), list), r3)
sys.exit(0 if ok else 1)