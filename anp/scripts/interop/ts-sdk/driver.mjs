// The official ANP TypeScript SDK (@awiki/anp-typescript-sdk 0.9.5, Apache-2.0) checking this project, and this project checking it.
// Run by scripts/interop/run.ps1 with the SDK installed in an isolated folder by scripts/interop/ts-sdk-build.ps1.
//
//   make DIR HOST NAME                 create an e1 DID (NAME.did.json, NAME.key.pem)
//   didcheck DOC.json                  validate a DID document (binding and proof)
//   httpverify mine.http.json          verify a request signed by this project
//   httpsign DIR                       sign a request (tssdk.http.json) for this project to verify
//   cases OUT.json                     the SDK's verdict on a table of handles
//   wns BASE                           resolve and verify the handles a running node provides
//   live BASE DOC KEY MODE             call a running node (MODE: http | legacy)
import fs from "node:fs";
import * as sdk from "@awiki/anp-typescript-sdk";

let failed = false;
const check = (name, ok, detail = "") => {
  if (ok) console.log("PASS  " + name);
  else { failed = true; console.log("FAIL  " + name + "  " + String(detail).slice(0, 300)); }
};
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const [cmd, ...a] = process.argv.slice(2);

function make(dir, host, name) {
  const b = sdk.createDidWbaDocument(host, { pathSegments: ["agents", name], didProfile: "e1", enableE2ee: false });
  fs.writeFileSync(`${dir}/${name}.did.json`, JSON.stringify(b.didDocument, null, 1));
  fs.writeFileSync(`${dir}/${name}.key.pem`, b.keys["key-1"].privateKeyPem);
  console.log("created", b.didDocument.id);
  return b;
}

async function call(method, url, body, headers) {
  try {
    const r = await fetch(url, { method, body, headers });
    const h = {}; r.headers.forEach((v, k) => (h[k] = v));
    return { status: r.status, text: await r.text(), headers: h };
  } catch (e) { return { status: -1, text: String(e), headers: {} }; }
}

if (cmd === "make") make(a[0], a[1], a[2]);

else if (cmd === "didcheck") {
  const doc = readJson(a[0]);
  let ok = false, why = "";
  try { ok = sdk.validateDidDocumentBinding(doc, true); } catch (e) { why = e.message; }
  check(`the TypeScript SDK validates ${doc.id.slice(0, 40)}... (e1 binding and proof)`, ok, why);
}

else if (cmd === "httpverify") {
  const fx = readJson(a[0]);
  let ok = false, why = "";
  try { sdk.verifyHttpMessageSignature(fx.did_document, fx.method, fx.url, fx.headers, fx.body); ok = true; } catch (e) { why = e.message; }
  check("TypeScript SDK verifies a request signed by my Rust code", ok, why);
  let refused = false;
  try { sdk.verifyHttpMessageSignature(fx.did_document, fx.method, fx.url, fx.headers, '{"jsonrpc":"2.0","method":"Other"}'); } catch { refused = true; }
  check("...and refuses it with a changed body", refused);
}

else if (cmd === "httpsign") {
  const b = make(a[0], "tssdk.example.com", "tsbot");
  const url = "https://node.example.com:8800/rpc?x=1", body = '{"jsonrpc":"2.0","method":"ListTasks"}';
  const headers = sdk.generateHttpSignatureHeaders(b.didDocument, url, "POST", b.keys["key-1"].privateKeyPem, undefined, body);
  fs.writeFileSync(`${a[0]}/tssdk.http.json`, JSON.stringify({ did_document: b.didDocument, method: "POST", url, body, headers }, null, 1));
  console.log("the TypeScript SDK signed a request as", b.didDocument.id.slice(0, 50) + "...");
}

else if (cmd === "cases") {
  const cases = readJson(a[1] ?? a[0]).cases;
  const rows = cases.map((c) => {
    try {
      if (c.input.startsWith("wba://")) { const p = sdk.parseWbaUri(c.input); return { input: c.input, valid: true, normalized: p.handle }; }
      const [l, d] = sdk.validateHandle(c.input); return { input: c.input, valid: true, normalized: `${l}.${d}` };
    }
    catch { return { input: c.input, valid: false }; }
  });
  fs.writeFileSync(a[0], JSON.stringify({ cases: rows }, null, 1));
  console.log("SDK verdicts written:", rows.filter((r) => r.valid).length, "valid of", rows.length);
}

else if (cmd === "wns") {
  const base = a[0].replace(/\/$/, "");
  const sec = JSON.parse((await call("GET", base + "/security")).text);
  const did = sec.did;
  const didDoc = JSON.parse((await call("GET", `${base}/${did.split(":").slice(3).join("/")}/did.json`)).text);
  const opts = { baseUrlOverride: base };
  let doc;
  try { doc = await sdk.resolveHandle("agent.wns.example.com", opts); } catch (e) { check("the TypeScript SDK resolves the node's handle", false, e.message); }
  if (doc) {
    check("the TypeScript SDK resolves the node's handle (DID, active, generation 1, ttl 300)", doc.did === did && doc.status === "active" && doc.binding_generation === "1" && doc.ttl === 300, JSON.stringify(doc));
    check("the profile is kept (same DID and handle, display name, agent)", doc.profile && doc.profile.subject_did === did && doc.profile.handle === "agent.wns.example.com", JSON.stringify(doc.profile));
  }
  try { await sdk.resolveHandle("nobody.wns.example.com", opts); check("an unknown handle is not found", false); }
  catch (e) { check("an unknown handle is HandleNotFoundError (404)", e instanceof sdk.HandleNotFoundError, e.constructor.name + " " + e.message); }
  const svc = didDoc.service.filter((s) => s.type === "ANPHandleService");
  check("the DID document has one ANPHandleService per handle", svc.length === 2, JSON.stringify(svc));
  const mine = sdk.buildHandleServiceEntry(did, "agent", "wns.example.com");
  check("and the first is what the SDK's buildHandleServiceEntry makes", svc.some((s) => JSON.stringify(s) === JSON.stringify(mine)) || svc.some((s) => s.id === mine.id && s.type === mine.type && s.serviceEndpoint === mine.serviceEndpoint), JSON.stringify([mine, svc]));
  let r = await sdk.verifyHandleBinding("agent.wns.example.com", { didDocument: didDoc, resolutionOptions: opts });
  check("verifyHandleBinding accepts the binding both ways", r.isValid && r.forwardVerified && r.reverseVerified && r.bindingGeneration === "1", JSON.stringify(r));
  const stripped = { ...didDoc, service: didDoc.service.filter((s) => s.type !== "ANPHandleService") };
  r = await sdk.verifyHandleBinding("agent.wns.example.com", { didDocument: stripped, resolutionOptions: opts });
  check("with the ANPHandleService entries removed it refuses (reverse half missing)", !r.isValid && r.forwardVerified && !r.reverseVerified, JSON.stringify(r));
}

else if (cmd === "live") {
  const [base0, docPath, keyPath, mode] = a;
  const base = base0.replace(/\/$/, "");
  const c = new sdk.DIDWbaAuthHeader(docPath, keyPath, mode === "legacy" ? sdk.AuthMode.LegacyDidWba : sdk.AuthMode.HttpSignatures);
  const rpc = '{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-ts-1","role":"ROLE_USER","parts":[{"text":"hello from the TypeScript SDK"}]}}}';
  let r = await call("POST", base + "/", rpc, { "Content-Type": "application/json" });
  check("an unsigned JSON-RPC call is refused with 401", r.status === 401, r.status + r.text);
  if (mode === "http") {
    let h = await c.getAuthHeaders(base + "/", true, "POST", { "Content-Type": "application/json" }, rpc);
    r = await call("POST", base + "/", rpc, { ...h, "Content-Type": "application/json" });
    check("a call signed by the TypeScript SDK is accepted and answered (a completed task)", r.status === 200 && r.text.includes("TASK_STATE_COMPLETED"), r.status + r.text);
    r = await call("POST", base + "/", rpc, { ...h, "Content-Type": "application/json" });
    check("the same signed request again (a replay) is refused", r.status === 401, r.status);
    h = await c.getAuthHeaders(base + "/", true, "POST", { "Content-Type": "application/json" }, rpc);
    r = await call("POST", base + "/", rpc.replace("hello", "HELLO"), { ...h, "Content-Type": "application/json" });
    check("a body changed in transit is refused", r.status === 401, r.status);
    h = await c.getAuthHeaders(base + "/agents", true, "GET");
    r = await call("GET", base + "/agents", undefined, h);
    check("a signed GET of the mesh directory works", r.status === 200, r.status + r.text);
  } else {
    const h = await c.getAuthHeaders(base + "/agents", true, "GET");
    check("the TypeScript SDK builds a legacy DIDWba header", (h.Authorization ?? h.authorization ?? "").startsWith("DIDWba "), JSON.stringify(h));
    r = await call("GET", base + "/agents", undefined, h);
    check("the header is accepted (GET of the mesh directory)", r.status === 200, r.status + r.text);
    const info = r.headers["authentication-info"] ?? "";
    check("the node answers with an Authentication-Info token", info.includes("access_token="), JSON.stringify(r.headers));
    const tok = c.updateToken(base + "/agents", r.headers);
    check("the TypeScript SDK stores that token", !!tok);
    const h2 = await c.getAuthHeaders(base + "/agents", false, "GET");
    check("it now sends the Bearer token", (h2.Authorization ?? h2.authorization) === "Bearer " + tok, JSON.stringify(h2));
    r = await call("POST", base + "/", rpc, { ...h2, "Content-Type": "application/json" });
    check("a JSON-RPC call with the Bearer token is answered", r.status === 200 && r.text.includes("TASK_STATE_COMPLETED"), r.status + r.text);
    r = await call("GET", base + "/agents", undefined, h);
    check("the same DIDWba header sent again (a replay) is refused", r.status === 401, r.status);
    r = await call("GET", base + "/agents", undefined, { Authorization: "Bearer " + tok.slice(0, -4) + "AAAA" });
    check("a Bearer token with a damaged signature is refused", r.status === 401, r.status);
  }
}

else { console.log("see the file header"); process.exit(2); }
process.exit(failed ? 1 : 0);