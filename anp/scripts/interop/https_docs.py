"""A small HTTPS server that publishes DID documents the way a domain would: /agents/<name>/<e1...>/did.json.

  https_docs.py CERT_DIR PORT DOC.json...   (every document is served at the path its DID names; others give 404)
"""
import http.server, json, ssl, sys
from urllib.parse import unquote
cert, port, files = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
docs = {}
for f in files:
    d = json.load(open(f))
    parts = d["id"].split(":")[3:]
    docs["/" + "/".join(parts) + "/did.json"] = json.dumps(d).encode()
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        b = docs.get(unquote(self.path))
        self.send_response(200 if b else 404)
        self.send_header("Content-Type", "application/did+json" if b else "text/plain")
        body = b or b"not found\n"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        print(self.address_string(), self.path, flush=True)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f"{cert}/server.pem", f"{cert}/server.key")
s = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
print("serving", sorted(docs), flush=True)
s.serve_forever()