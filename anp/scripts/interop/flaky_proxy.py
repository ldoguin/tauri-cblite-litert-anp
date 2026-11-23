"""A stand-in for an unreliable network: answers the first N POSTs with 503, then forwards everything to a real endpoint.

  flaky_proxy.py LISTEN_PORT TARGET_PORT FAILS
"""
import http.client, http.server, sys
listen, target, fails = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
n = 0
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        global n
        n += 1
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if n <= fails:
            print(f"POST {n}: 503 (down)", flush=True)
            out, code = b"unavailable\n", 503
        else:
            print(f"POST {n}: forwarded", flush=True)
            c = http.client.HTTPConnection("127.0.0.1", target, timeout=30)
            c.request("POST", self.path, body, {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")})
            r = c.getresponse()
            out, code = r.read(), r.status
        self.send_response(code)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("0.0.0.0", listen), H).serve_forever()