"""The search agent's rate limit: the methods that make it fetch are rationed per client, searching is not.

  search_limits.py BASE      (the agent was started with --rate-limit 3 --rate-seconds 600)
"""
import json, sys, urllib.request, urllib.error
BASE = sys.argv[1].rstrip("/")

def rpc(method, **params):
    req = urllib.request.Request(BASE + "/", data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}"), dict(e.headers)

ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)[:300]))

codes = [rpc("register", url="http://not-https.example.com/ad.json")[0] for _ in range(3)]
check("the first three registrations go through (and are refused for being plain http, not for being too many)", codes == [200, 200, 200], codes)
s, body, h = rpc("register", url="http://not-https.example.com/ad.json")
check("the fourth is answered 429 with a Retry-After", s == 429 and int({k.lower(): v for k, v in h.items()}.get("retry-after", "0")) > 0, (s, h))
check("and a JSON-RPC error that says so", body.get("error", {}).get("code") == -32029, body)
s, body, _ = rpc("crawl", domain="example.com")
check("crawl shares the same ration", s == 429, s)
for _ in range(10):
    s, body, _ = rpc("search", query="anything")
check("searching is not rationed", s == 200 and "results" in body.get("result", {}), (s, body))
s, body, _ = rpc("list")
check("neither is listing", s == 200, s)
sys.exit(0 if ok else 1)