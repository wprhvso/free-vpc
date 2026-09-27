import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class MetaHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/keys":
            qs = parse_qs(parsed.query)
            ip = qs.get("ip", [""])[0]
            key_file = f"/tmp/keys_{ip}"
            if ip and os.path.exists(key_file):
                with open(key_file, "r") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(data.encode())
                return
            self.send_response(204)
            self.end_headers()
            return
        if parsed.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/set_keys":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            qs = parse_qs(parsed.query)
            ip = qs.get("ip", [""])[0]
            if ip and body:
                with open(f"/tmp/keys_{ip}", "w") as f:
                    f.write(body)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
                return
            self.send_response(400)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 18080
    server = HTTPServer((host, port), MetaHandler)
    server.serve_forever()
