"""Use the official ANP SDK to create an e1 DID document, and (if given) to validate ours."""
import json, sys
import os
OUT = os.environ.get("INTEROP_OUT", "/mnt/c/cbt-anp/interop")
LIBS = os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs"))
sys.path.insert(0, LIBS)
from anp.authentication.did_wba import create_did_wba_document, validate_did_document_binding

out = OUT
doc, keys = create_did_wba_document(
    hostname="sdk.example.com",
    path_segments=["agents", "sdkbot"],
    agent_description_url="https://sdk.example.com/agents/sdkbot/ad.json",
    did_profile="e1",
)
json.dump(doc, open(f"{out}/sdk.did.json", "w"), indent=2)
print("SDK created:", doc["id"])
print("SDK validates its own document:", validate_did_document_binding(doc, verify_proof=True))
print("keys:", sorted(keys))

for name in sys.argv[1:]:
    mine = json.load(open(f"{out}/{name}"))
    print(f"SDK validates {name} ({mine['id'][:48]}...):", validate_did_document_binding(mine, verify_proof=True))
