"""A TLS-terminating reverse proxy: what a node's domain looks like from outside (https, a CA-signed certificate), in front of a
node that speaks plain HTTP.

  tls_proxy.py CERT_DIR LISTEN_PORT TARGET_HOST TARGET_PORT
"""
import http.client, http.server, ssl, sys
cert, listen, host, port = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def forward(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n) if n else None
        c = http.client.HTTPConnection(host, port, timeout=60)
        c.request(self.command, self.path, body, {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")})
        r = c.getresponse()
        data = r.read()
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length", "date", "server"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    do_GET = do_POST = forward
    def log_message(self, *a):
        pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f"{cert}/server.pem", f"{cert}/server.key")
s = http.server.ThreadingHTTPServer(("0.0.0.0", listen), H)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()