// The official ANP Go SDK (github.com/agent-network-protocol/anp/golang, v1.0.7, Apache-2.0) checking this project, and this
// project checking it. Built in an isolated folder by scripts/interop/go-sdk-build.ps1; nothing here is part of the product.
//
//	make <dir> <host> <port|0> <name>         create an e1 DID with the SDK (name.did.json, name.key.pem)
//	didcheck <doc.json>                       the SDK validates a DID document (binding and proof)
//	p5 <fixture>                              the SDK checks the P5 v2 objects of mine.p5.json
//	httpverify <mine.http.json>               the SDK verifies a request signed by this project
//	httpsign <dir>                            the SDK signs a request (gosdk.http.json) for this project to verify
//	wire <mine.wire.json> <t_init> <t_cipher> <fixture> <out>   parse this project's wire objects; build the SDK's
//	live <base> <doc.json> <key.pem> <mode>   call a running node (mode: http | legacy)
//	group <mine.group.json> <vectors.json> <out>   P6: parse this project's requests, compare AAD, build requests for this project to parse
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	anp "github.com/agent-network-protocol/anp/golang"
	auth "github.com/agent-network-protocol/anp/golang/authentication"
	group "github.com/agent-network-protocol/anp/golang/group_e2ee"
	e2ee "github.com/agent-network-protocol/anp/golang/direct_e2ee"
)

var failed bool

func check(name string, ok bool, detail string) {
	if ok {
		fmt.Println("PASS  " + name)
		return
	}
	failed = true
	if len(detail) > 300 {
		detail = detail[:300]
	}
	fmt.Println("FAIL  " + name + "  " + detail)
}

func readJSON(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		panic(fmt.Sprintf("%s: %v", path, err))
	}
	return v
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		panic(err)
	}
}

func decode[T any](v any) T {
	b, _ := json.Marshal(v)
	var t T
	if err := json.Unmarshal(b, &t); err != nil {
		panic(err)
	}
	return t
}

func str(v any) string { s, _ := v.(string); return s }

func make_(dir, host string, port int, name string) {
	p := &port
	if port == 0 {
		p = nil
	}
	e2eeOff := false
	bundle, err := auth.CreateDidWBADocument(host, auth.DidDocumentOptions{Port: p, PathSegments: []string{"agents", name}, DidProfile: auth.DidProfileE1, EnableE2EE: &e2eeOff})
	if err != nil {
		panic(err)
	}
	writeJSON(dir+"/"+name+".did.json", bundle.DidDocument)
	if err := os.WriteFile(dir+"/"+name+".key.pem", []byte(bundle.Keys["key-1"].PrivateKeyPEM), 0o600); err != nil {
		panic(err)
	}
	fmt.Println("created", bundle.DidDocument["id"])
}

func didcheck(path string) {
	doc := readJSON(path)
	check("the Go SDK validates "+str(doc["id"])[:40]+"... (e1 binding and proof)", auth.ValidateDIDDocumentBinding(doc, true), "")
}

func p5(path string) {
	fx := readJSON(path)
	rcpt := fx["recipient"].(map[string]any)
	now, err := time.Parse(time.RFC3339, str(fx["now"]))
	if err != nil {
		panic(err)
	}
	bundle := decode[e2ee.V2PrekeyBundle](rcpt["bundle"])
	err = e2ee.VerifyPrekeyBundleV2(bundle, rcpt["did_document"].(map[string]any), now)
	check("Go SDK accepts my prekey bundle against my DID document and device manifest", err == nil, fmt.Sprint(err))

	sender := fx["sender"].(map[string]any)
	meta := decode[e2ee.V2DirectMetadata](map[string]any{
		"profile": "anp.direct.e2ee.v2", "security_profile": "direct-e2ee",
		"sender_did": sender["did"], "sender_device_id": sender["device_id"],
		"target": map[string]any{"kind": "agent", "did": rcpt["did_document"].(map[string]any)["id"]},
		"recipient_device_id": rcpt["device_id"],
		"operation_id":        fx["message_id"], "message_id": fx["message_id"],
		"content_type": "application/anp-direct-init+json",
	})
	body := decode[e2ee.V2DirectInitBody](fx["init_body"])
	aad, err := e2ee.BuildInitAADV2(meta, body)
	check("Go SDK builds the same init AAD as my code", err == nil && string(aad) == str(fx["expected_ad_init"]), fmt.Sprintf("\n go  : %s\n mine: %s (%v)", aad, fx["expected_ad_init"], err))
	check("Go SDK accepts the shape of my init body", body.Validate() == nil, fmt.Sprint(body.Validate()))

	var ap e2ee.V2ApplicationPlaintext
	b, _ := json.Marshal(fx["application_plaintext"])
	err = json.Unmarshal(b, &ap)
	if err == nil {
		var plain []byte
		plain, err = e2ee.CanonicalApplicationPlaintextV2(ap)
		check("Go SDK canonicalises my application plaintext identically (RFC 8785 numbers too)", err == nil && string(plain) == str(fx["expected_application_plaintext_jcs"]), fmt.Sprintf("\n go  : %s\n mine: %s (%v)", plain, fx["expected_application_plaintext_jcs"], err))
	} else {
		check("Go SDK reads my application plaintext", false, err.Error())
	}
}

func httpverify(path string) {
	fx := readJSON(path)
	headers := map[string]string{}
	for k, v := range fx["headers"].(map[string]any) {
		headers[k] = str(v)
	}
	_, err := auth.VerifyHTTPMessageSignature(fx["did_document"].(map[string]any), str(fx["method"]), str(fx["url"]), headers, []byte(str(fx["body"])))
	check("Go SDK verifies a request signed by my Rust code", err == nil, fmt.Sprint(err))
	_, err = auth.VerifyHTTPMessageSignature(fx["did_document"].(map[string]any), str(fx["method"]), str(fx["url"]), headers, []byte(`{"jsonrpc":"2.0","method":"Other"}`))
	check("...and refuses it with a changed body", err != nil, "")
}

func httpsign(dir string) {
	make_(dir, "gosdk.example.com", 0, "gosdkbot")
	doc := readJSON(dir + "/gosdkbot.did.json")
	pem, _ := os.ReadFile(dir + "/gosdkbot.key.pem")
	key, err := anp.PrivateKeyFromPEM(string(pem))
	if err != nil {
		panic(err)
	}
	url, body := "https://node.example.com:8800/rpc?x=1", `{"jsonrpc":"2.0","method":"ListTasks"}`
	headers, err := auth.GenerateHTTPSignatureHeaders(doc, url, "POST", key, nil, []byte(body), auth.HttpSignatureOptions{})
	if err != nil {
		panic(err)
	}
	writeJSON(dir+"/gosdk.http.json", map[string]any{"did_document": doc, "method": "POST", "url": url, "body": body, "headers": headers})
	fmt.Println("the Go SDK signed a request as", str(doc["id"])[:50]+"...")
}

func wire(minePath, tInit, tCipher, fxPath, out string) {
	mine, fx := readJSON(minePath), readJSON(fxPath)
	ti, tc := readJSON(tInit), readJSON(tCipher)
	parse := func(name string, err error) { check("the Go SDK parses this project's "+name, err == nil, fmt.Sprint(err)) }
	_, _, err := e2ee.ParseDirectSendRequestV2(mine["direct_init"])
	parse("direct.send init request", err)
	_, _, err = e2ee.ParseDirectSendRequestV2(mine["direct_cipher"])
	parse("direct.send follow-up request", err)
	_, _, err = e2ee.ParsePublishPrekeyBundleRequestV2(mine["publish"])
	parse("publish_prekey_bundle request", err)
	_, _, err = e2ee.ParseGetPrekeyBundleRequestV2(mine["get"])
	parse("get_prekey_bundle request", err)
	r1, err := e2ee.ParseDirectSendResultV2(mine["direct_send_result"])
	parse("direct.send result", err)
	r2, err := e2ee.ParsePublishPrekeyBundleResultV2(mine["publish_result"])
	parse("publish result", err)
	r3, err := e2ee.ParseGetPrekeyBundleResultV2(mine["get_result"])
	parse("get result", err)

	im := ti["messages"].([]any)[0].(map[string]any)
	cm := tc["messages"].([]any)[0].(map[string]any)
	rcpt := fx["recipient"].(map[string]any)
	bobDID, bobDev := str(rcpt["did_document"].(map[string]any)["id"]), str(rcpt["device_id"])
	initMeta, cipherMeta := decode[e2ee.V2DirectMetadata](im["metadata"]), decode[e2ee.V2DirectMetadata](cm["metadata"])
	svc := func(sender, dev, op string) e2ee.V2KeyServiceMetadata {
		return decode[e2ee.V2KeyServiceMetadata](map[string]any{"profile": "anp.direct.e2ee.v2", "security_profile": "transport-protected", "sender_did": sender, "sender_device_id": dev,
			"target": map[string]any{"kind": "service", "did": "did:wba:b.example.com:services:message"}, "operation_id": op})
	}
	must := func(v map[string]any, err error) map[string]any {
		if err != nil {
			panic(err)
		}
		return v
	}
	opk := map[string]any{"key_id": "opk-interop-1", "public_key_b64u": "UKYUCbHd0DJemxa3AOcZ6XcsBwALG9d4bpB8ZT0gSV0"}
	pub := decode[e2ee.V2PublishPrekeyBundleBody](map[string]any{"prekey_bundle": rcpt["bundle"], "one_time_prekeys": []any{opk}})
	get := decode[e2ee.V2GetPrekeyBundleBody](map[string]any{"target_did": bobDID, "target_device_id": bobDev, "preferred_suite": "ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1", "require_opk": true})
	toMap := func(v any) any { b, _ := json.Marshal(v); var m any; _ = json.Unmarshal(b, &m); return m }
	outv := map[string]any{
		"direct_init":        must(e2ee.DirectSendRequestV2(initMeta, decode[e2ee.V2DirectInitBody](im["body"]))),
		"direct_cipher":      must(e2ee.DirectSendRequestV2(cipherMeta, decode[e2ee.V2DirectCipherBody](cm["body"]))),
		"publish":            must(e2ee.PublishPrekeyBundleRequestV2(svc(bobDID, bobDev, "op-publish-1"), pub)),
		"get":                must(e2ee.GetPrekeyBundleRequestV2(svc(str(initMeta.SenderDID), initMeta.SenderDeviceID, "op-get-1"), get)),
		"direct_send_result": toMap(r1),
		"publish_result":     toMap(r2),
		"get_result":         toMap(r3),
	}
	writeJSON(out, outv)
}

type reply struct {
	status  int
	body    string
	headers map[string]string
}

func call(method, url string, body []byte, headers map[string]string) reply {
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return reply{status: -1, body: err.Error()}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	h := map[string]string{}
	for k := range resp.Header {
		h[k] = resp.Header.Get(k)
	}
	return reply{resp.StatusCode, string(b), h}
}

func live(base, docPath, keyPath, mode string) {
	base = strings.TrimRight(base, "/")
	am := auth.AuthModeHTTPSignatures
	if mode == "legacy" {
		am = auth.AuthModeLegacyDidWba
	}
	c := auth.NewDIDWbaAuthHeader(docPath, keyPath, am)
	rpc := []byte(`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-go-1","role":"ROLE_USER","parts":[{"text":"hello from the Go SDK"}]}}}`)
	r := call("POST", base+"/", rpc, map[string]string{"Content-Type": "application/json"})
	check("an unsigned JSON-RPC call is refused with 401", r.status == 401, fmt.Sprint(r.status, r.body))

	if mode == "http" {
		h, err := c.GetAuthHeader(base+"/", true, "POST", map[string]string{"Content-Type": "application/json"}, rpc)
		if err != nil {
			panic(err)
		}
		h["Content-Type"] = "application/json"
		r = call("POST", base+"/", rpc, h)
		var v map[string]any
		_ = json.Unmarshal([]byte(r.body), &v)
		state := ""
		if res, ok := v["result"].(map[string]any); ok {
			if t, ok := res["task"].(map[string]any); ok {
				state = str(t["status"].(map[string]any)["state"])
			}
		}
		check("a call signed by the Go SDK is accepted and answered (a completed task)", r.status == 200 && state == "TASK_STATE_COMPLETED", fmt.Sprint(r.status, r.body))
		r = call("POST", base+"/", rpc, h)
		check("the same signed request again (a replay) is refused", r.status == 401, fmt.Sprint(r.status))
		h2, _ := c.GetAuthHeader(base+"/", true, "POST", map[string]string{"Content-Type": "application/json"}, rpc)
		h2["Content-Type"] = "application/json"
		r = call("POST", base+"/", bytes.ReplaceAll(rpc, []byte("hello"), []byte("HELLO")), h2)
		check("a body changed in transit is refused", r.status == 401, fmt.Sprint(r.status))
		h3, _ := c.GetAuthHeader(base+"/agents", true, "GET", nil, nil)
		r = call("GET", base+"/agents", nil, h3)
		check("a signed GET of the mesh directory works", r.status == 200, fmt.Sprint(r.status, r.body))
		return
	}

	h, err := c.GetAuthHeader(base+"/agents", true, "GET", nil, nil)
	if err != nil {
		panic(err)
	}
	check("the Go SDK builds a legacy DIDWba header", strings.HasPrefix(h["Authorization"], "DIDWba "), fmt.Sprint(h))
	r = call("GET", base+"/agents", nil, h)
	check("the header is accepted (GET of the mesh directory)", r.status == 200, fmt.Sprint(r.status, r.body))
	info := ""
	for k, v := range r.headers {
		if strings.EqualFold(k, "Authentication-Info") {
			info = v
		}
	}
	check("the node answers with an Authentication-Info token", strings.Contains(info, "access_token="), fmt.Sprint(r.headers))
	tok := c.UpdateToken(base+"/agents", r.headers)
	check("the Go SDK stores that token", tok != "", "")
	h2, _ := c.GetAuthHeader(base+"/agents", false, "GET", nil, nil)
	check("the Go SDK now sends the Bearer token", h2["Authorization"] == "Bearer "+tok, fmt.Sprint(h2))
	h2["Content-Type"] = "application/json"
	r = call("POST", base+"/", rpc, h2)
	check("a JSON-RPC call with the Bearer token is answered", r.status == 200 && strings.Contains(r.body, "TASK_STATE_COMPLETED"), fmt.Sprint(r.status, r.body))
	r = call("GET", base+"/agents", nil, h)
	check("the same DIDWba header sent again (a replay) is refused", r.status == 401, fmt.Sprint(r.status))
	r = call("GET", base+"/agents", nil, map[string]string{"Authorization": "Bearer " + tok[:len(tok)-4] + "AAAA"})
	check("a Bearer token with a damaged signature is refused", r.status == 401, fmt.Sprint(r.status))
}

func groupCheck(minePath, vecPath, out string) {
	mine, vec := readJSON(minePath), readJSON(vecPath)
	reqs := mine["requests"].(map[string]any)
	_, _, _, err := group.ParseGroupSendRequestV2(reqs["send"])
	check("the Go SDK parses a group.e2ee.send request this project built (with its own origin proof)", err == nil, fmt.Sprint(err))
	_, _, _, err = group.ParseGroupIncomingNotificationV2(reqs["incoming"])
	check("the Go SDK parses a group.incoming notification this project built (with the preserved origin context)", err == nil, fmt.Sprint(err))
	if reqs["publish"] != nil {
		_, _, err = group.ParsePublishKeyPackageRequestV2(reqs["publish"])
		check("the Go SDK parses a publish_key_package request carrying a binding this project signed", err == nil, fmt.Sprint(err))
	}
	sm, sb, _, err := group.ParseGroupSendRequestV2(reqs["send"])
	if err == nil {
		ad, e2 := group.GroupSendAuthenticatedDataV2(sm, sb)
		check("the Go SDK's MLS authenticated data for that send is byte-for-byte this project's", e2 == nil && string(ad) == str(mine["expected_send_ad"]), fmt.Sprintf("\n go  : %s\n mine: %s (%v)", ad, mine["expected_send_ad"], e2))
	}
	// the other direction: the Go SDK rebuilds every request of the shared vectors
	built := map[string]any{}
	rebuild := func(name string, f func() (map[string]any, error)) {
		r, e := f()
		check("the Go SDK builds the "+name+" request from the shared vectors", e == nil, fmt.Sprint(e))
		built[name] = r
	}
	pm, pb, e := group.ParsePublishKeyPackageRequestV2(vec["publish_request"])
	if e == nil {
		rebuild("publish", func() (map[string]any, error) { return group.PublishKeyPackageRequestV2(pm, pb) })
	}
	gm, gb, e := group.ParseGetKeyPackageRequestV2(vec["get_request"])
	if e == nil {
		rebuild("get", func() (map[string]any, error) { return group.GetKeyPackageRequestV2(gm, gb) })
	}
	cm, cb, ca, e := group.ParseGroupCreateRequestV2(vec["create_request"])
	if e == nil {
		rebuild("create", func() (map[string]any, error) { return group.GroupCreateRequestV2(cm, cb, ca) })
	}
	am, ab, aa, e := group.ParseGroupAddRequestV2(vec["add_request"])
	if e == nil {
		rebuild("add", func() (map[string]any, error) { return group.GroupAddRequestV2(am, ab, aa) })
	}
	rm, rb, ra, e := group.ParseGroupRemoveRequestV2(vec["remove_request"])
	if e == nil {
		rebuild("remove", func() (map[string]any, error) { return group.GroupRemoveRequestV2(rm, rb, ra) })
	}
	sm2, sb2, sa2, e := group.ParseGroupSendRequestV2(vec["send_request"])
	if e == nil {
		rebuild("send", func() (map[string]any, error) { return group.GroupSendRequestV2(sm2, sb2, sa2) })
	}
	nm, nb, e := group.ParseGroupNoticeNotificationV2(vec["notice_notification"])
	if e == nil {
		rebuild("notice", func() (map[string]any, error) { return group.GroupNoticeNotificationV2(nm, nb) })
	}
	im, ib, ia, e := group.ParseGroupIncomingNotificationV2(vec["incoming_notification"])
	if e == nil {
		rebuild("incoming", func() (map[string]any, error) { return group.GroupIncomingNotificationV2(im, ib, ia) })
	}
	writeJSON(out, built)
}
func main() {
	a := os.Args[1:]
	if len(a) == 0 {
		fmt.Println("usage: see the file header")
		os.Exit(2)
	}
	_ = context.Background()
	switch a[0] {
	case "make":
		port, _ := strconv.Atoi(a[3])
		make_(a[1], a[2], port, a[4-0])
	case "didcheck":
		didcheck(a[1])
	case "p5":
		p5(a[1])
	case "httpverify":
		httpverify(a[1])
	case "httpsign":
		httpsign(a[1])
	case "wire":
		wire(a[1], a[2], a[3], a[4], a[5])
	case "live":
		live(a[1], a[2], a[3], a[4])
	case "group":
		groupCheck(a[1], a[2], a[3])
	default:
		fmt.Println("unknown command", a[0])
		os.Exit(2)
	}
	if failed {
		os.Exit(1)
	}
}