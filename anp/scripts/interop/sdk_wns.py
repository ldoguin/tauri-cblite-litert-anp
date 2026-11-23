"""ANP-04 WNS with the official SDK.

  sdk_wns.py cases                 the SDK's verdict on a table of handles, for this project to compare (wns_cases.json)
  sdk_wns.py node BASE             the SDK resolves and verifies the handles a running node provides (agent.wns.example.com, desk.wns.example.com)
  sdk_wns.py serve PORT            serve handle documents built with the SDK's own models, for this project's client to resolve

The SDK resolves over https://<domain>/.well-known/handle/<local>; port 443 and a certificate for the domain are not available
here, so `node` points the SDK's URL builder at the node's own HTTP port. Everything else (parsing, validation, binding
verification) is the SDK's own.
"""
import asyncio, json, os, sys
OUT = os.environ.get("INTEROP_OUT", "/mnt/c/cbt-anp/interop")
sys.path.insert(0, os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs")))
from anp.wns import (validate_handle, normalize_handle, resolve_handle, verify_handle_binding, build_handle_service_entry,
                     HandleResolutionDocument, DIDSubjectProfile, HandleNotFoundError, HandleValidationError, canonicalize_binding_generation, compare_binding_generations)
import anp.wns.resolver as resolver_mod
from anp.authentication.did_wba import create_did_wba_document

mode = sys.argv[1]

CASES = ["alice.example.com", "Alice.Example.COM", "  alice.example.com  ", "a.example.com", "a-b.example.com", "a1.b2.example.com", "x" * 63 + ".example.com",
         "x" * 64 + ".example.com", "alice", "alice.", ".example.com", "", "-a.example.com", "a-.example.com", "a--b.example.com", "a_b.example.com",
         "alice.example", "alice.-example.com", "alice.example-.com", "alice.exa mple.com", "alice.example..com", "al\u00efce.example.com", "alice.exämple.com",
         "9lives.example.com", "a.b", "a.b.c", "alice.example.com.", "ALICE-1.EXAMPLE-DOMAIN.CO.UK", "a" + "." + "x" * 63 + ".com", "a." + "x" * 64 + ".com"]

if mode == "cases":
    rows = []
    for c in CASES:
        try:
            rows.append({"input": c, "valid": True, "normalized": normalize_handle(c)})
        except Exception:
            rows.append({"input": c, "valid": False})
    for c in ["wba://alice.example.com", "wba://", "wba://alice"]:
        # this project's `parse` takes bare handles and wba:// URIs; the SDK parses URIs separately
        from anp.wns import parse_wba_uri
        try:
            rows.append({"input": c, "valid": True, "normalized": parse_wba_uri(c).handle})
        except Exception:
            rows.append({"input": c, "valid": False})
    json.dump({"cases": rows}, open(f"{OUT}/wns_cases.json", "w"), indent=1)
    gens = [("1", "2"), ("9", "10"), ("123456789012345678901234567890", "123456789012345678901234567891"), ("5", "5")]
    print("SDK verdicts written:", sum(r["valid"] for r in rows), "valid of", len(rows), "; generations:", [compare_binding_generations(a, b) for a, b in gens])
    sys.exit(0)

ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)[:300]))

if mode == "node":
    import urllib.request
    BASE = sys.argv[2].rstrip("/")
    resolver_mod.build_resolution_url = lambda local, domain: f"{BASE}/.well-known/handle/{local}"
    sec = json.load(urllib.request.urlopen(BASE + "/security", timeout=20))
    did = sec["did"]
    did_path = "/" + "/".join(did.split(":")[3:]) + "/did.json"
    did_doc = json.load(urllib.request.urlopen(BASE + did_path, timeout=20))

    async def main():
        doc = await resolve_handle("agent.wns.example.com")
        check("the SDK resolves the node's handle and reads its document (handle, DID, active, generation, ttl)", doc.did == did and doc.status.value == "active" and doc.binding_generation == "1" and doc.ttl == 300, doc)
        check("the profile is kept: it describes the same DID and handle", doc.profile is not None and doc.profile.subject_did == did and doc.profile.handle == "agent.wns.example.com", doc.profile)
        check("the profile carries a display name and the subject type agent", doc.profile and doc.profile.display_name and doc.profile.subject_type.value == "agent", doc.profile)
        d2 = await resolve_handle("wba://desk.wns.example.com")
        check("a second handle of the same node resolves to the same DID (wba:// form too)", d2.did == did and d2.handle == "desk.wns.example.com", d2)
        try:
            await resolve_handle("nobody.wns.example.com")
            check("an unknown handle is not found", False)
        except HandleNotFoundError:
            check("an unknown handle is HandleNotFoundError (404)", True)
        svc = [s for s in did_doc["service"] if s["type"] == "ANPHandleService"]
        check("the DID document has one ANPHandleService per handle", len(svc) == 2, svc)
        check("and the first is exactly what the SDK's build_handle_service_entry makes", build_handle_service_entry(did, "agent", "wns.example.com") in svc, svc)
        r = await verify_handle_binding("agent.wns.example.com", did_document=did_doc)
        check("the SDK's verify_handle_binding accepts the binding both ways", r.is_valid and r.forward_verified and r.reverse_verified and r.binding_generation == "1", r)
        r = await verify_handle_binding("desk.wns.example.com", did_document=did_doc)
        check("...for the second handle too", r.is_valid, r)
        stripped = dict(did_doc, service=[s for s in did_doc["service"] if s["type"] != "ANPHandleService"])
        r = await verify_handle_binding("agent.wns.example.com", did_document=stripped)
        check("with the ANPHandleService entries removed the SDK refuses (reverse half missing)", not r.is_valid and r.forward_verified and not r.reverse_verified, r)
        elsewhere = dict(did_doc, service=[dict(s, serviceEndpoint=s["serviceEndpoint"].replace("wns.example.com", "evil.example.net")) if s["type"] == "ANPHandleService" else s for s in did_doc["service"]])
        r = await verify_handle_binding("agent.wns.example.com", did_document=elsewhere)
        check("with the provider changed to another domain the SDK refuses", not r.is_valid, r)
    asyncio.run(main())
    sys.exit(0 if ok else 1)

if mode == "serve":
    import http.server
    port = int(sys.argv[2])
    doc, keys = create_did_wba_document(hostname="sdk.example.com", path_segments=["agents", "sdkbot"], did_profile="e1")
    did = doc["id"]
    doc["service"] = list(doc.get("service", [])) + [build_handle_service_entry(did, "sdkbot", "sdk.example.com")]
    json.dump(doc, open(f"{OUT}/sdkbot.wns.did.json", "w"), indent=1)
    handle = "sdkbot.sdk.example.com"
    def res(**kw):
        base = dict(handle=handle, did=did, status="active", binding_generation="7", ttl=60, updated="2026-11-15T10:00:00Z",
                    profile=DIDSubjectProfile(subject_did=did, subject_type="agent", handle=handle, display_name="SDK Bot"))
        base.update(kw)
        return HandleResolutionDocument(**base).model_dump(mode="json", exclude_none=True)
    routes = {
        "sdkbot": (200, res()),
        "paused": (200, res(handle="paused.sdk.example.com", status="suspended", profile=None)),
        "liar": (200, res(handle="other.sdk.example.com", profile=None)),
        "foreign": (200, dict(res(handle="foreign.sdk.example.com", profile=None), did="did:wba:other.net:agents:x:e1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
        "badgen": (200, dict(res(handle="badgen.sdk.example.com", profile=None), binding_generation="007")),
        "old": (410, {}),
        "moved": (301, {}),
    }
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            local = self.path.rsplit("/", 1)[-1]
            code, body = routes.get(local, (404, {}))
            data = json.dumps(body).encode()
            self.send_response(code)
            if code == 301:
                self.send_header("Location", "https://new.example.com/.well-known/handle/moved")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *a):
            pass
    print("serving", sorted(routes), flush=True)
    http.server.ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()