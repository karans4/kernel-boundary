"""Serves the dashboard and proxies read-only queries to ClickHouse, so the
browser never talks to ClickHouse directly. Localhost only; reach it from the
host with an SSH port-forward into the VM."""

import os
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CH_URL = os.environ.get("CH_URL", "http://localhost:8123")
HERE = Path(__file__).parent
PORT = int(os.environ.get("KB_DASH_PORT", "8080"))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/q?"):
            return self._query()
        path = "index.html" if self.path in ("/", "") else self.path.lstrip("/").split("?")[0]
        file = HERE / path
        if not file.is_file() or HERE not in file.resolve().parents:
            self.send_error(404)
            return
        ctype = {"html": "text/html", "js": "text/javascript", "css": "text/css"}.get(
            file.suffix.lstrip("."), "text/plain")
        self._send(200, file.read_bytes(), ctype)

    def _query(self):
        sql = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("sql", [""])[0]
        try:
            fmt = "" if "FORMAT" in sql.upper() else " FORMAT JSON"
            body = urllib.request.urlopen(
                urllib.request.Request(f"{CH_URL}/", data=(sql + fmt).encode()), timeout=10).read()
            self._send(200, body, "application/json")
        except Exception as error:
            self._send(200, f'{{"error":{error!r}}}'.encode(), "application/json")

    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"dashboard on 127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
