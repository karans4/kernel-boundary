"""The credential broker: the one door a guarded agent has to the outside.

An agent is handed placeholder keys and, by the kernel boundary, can reach
nothing but this broker on loopback. The broker swaps a placeholder for the
real credential only when the request is in scope for that route, forwards it,
and records every decision. A prompt-injected agent that leaks its key leaks a
placeholder; one that calls out of scope is refused here; one that tries to
reach the internet directly is killed by the kernel.

Routes and real secrets come from the environment; nothing real is committed.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CH_URL = os.environ.get("CH_URL", "http://localhost:8123")
LISTEN = ("127.0.0.1", int(os.environ.get("KB_BROKER_PORT", "8899")))
REPO = os.environ.get("GITHUB_REPO", "karans4/kb-demo-target")

# route name -> upstream base, the real auth it injects, the placeholder the
# agent must present, and the only (methods, path) shapes it will forward.
ROUTES = {
    "gh": {
        "base": "https://api.github.com",
        "auth": f"Bearer {os.environ.get('GITHUB_TOKEN', '')}",
        "placeholder": os.environ.get("GH_PLACEHOLDER", "ghp_PLACEHOLDER_scoped_to_one_repo_0"),
        "allow": [
            ({"GET"}, re.compile(rf"^/repos/{re.escape(REPO)}/(issues|pulls|actions|commits|contents)(/.*)?$")),
            ({"POST"}, re.compile(rf"^/repos/{re.escape(REPO)}/issues/\d+/comments$")),
        ],
    },
    "llm": {
        "base": "https://api.akashml.com/v1",
        "auth": f"Bearer {os.environ.get('AKASHML_API_KEY', '')}",
        "placeholder": os.environ.get("LLM_PLACEHOLDER", "akml-PLACEHOLDER_inference_only_0"),
        "allow": [
            ({"POST"}, re.compile(r"^/chat/completions$")),
            ({"GET"}, re.compile(r"^/models$")),
        ],
    },
}


def log(agent, route, method, target, decision, reason, status, latency_ms):
    print(f"BROKER {decision} {route} {method} {target} :: {reason}".rstrip(), file=sys.stderr, flush=True)
    row = {
        "ts": f"{time.time():.6f}", "agent": agent, "route": route, "method": method,
        "target": target[:512], "decision": decision, "reason": reason,
        "status": status, "latency_ms": round(latency_ms, 2),
    }
    try:
        req = urllib.request.Request(
            f"{CH_URL}/?query=INSERT%20INTO%20kb.broker%20FORMAT%20JSONEachRow",
            data=json.dumps(row).encode(), method="POST")
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        pass


def in_scope(route, method, path):
    return any(method in methods and pattern.match(path) for methods, pattern in ROUTES[route]["allow"])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _handle(self, method):
        started = time.time()
        agent = self.headers.get("X-KB-Agent", "unknown")
        raw = self.path.lstrip("/")
        name, _, rest = raw.partition("/")
        full = "/" + rest                      # path + any query, forwarded as-is
        path = full.split("?", 1)[0]           # path only, for scope matching
        route = ROUTES.get(name)
        if not route:
            log(agent, name, method, path, "refuse", "unknown route", 404, 0)
            return self._respond(404, b'{"error":"unknown route"}')

        presented = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if presented != route["placeholder"]:
            log(agent, name, method, path, "refuse", "bad placeholder", 401, 0)
            return self._respond(401, b'{"error":"present the issued placeholder key"}')

        if not in_scope(name, method, path):
            log(agent, name, method, path, "refuse", "out of scope for this key", 403,
                (time.time() - started) * 1000)
            return self._respond(403, b'{"error":"request is outside this key\'s scope"}')

        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length) if length else None

        upstream = urllib.request.Request(route["base"] + full, data=payload, method=method)
        if route["auth"].strip() != "Bearer":  # inject the real key; omit when unset (public read)
            upstream.add_header("Authorization", route["auth"])
        upstream.add_header("Accept", self.headers.get("Accept", "application/json"))
        if payload:
            upstream.add_header("Content-Type", self.headers.get("Content-Type", "application/json"))
        if name == "gh":
            upstream.add_header("X-GitHub-Api-Version", "2022-11-28")
        try:
            with urllib.request.urlopen(upstream, timeout=120) as resp:
                body, status = resp.read(), resp.status
        except urllib.error.HTTPError as err:
            body, status = err.read(), err.code
        except Exception as err:
            log(agent, name, method, path, "refuse", f"upstream error: {err}", 502,
                (time.time() - started) * 1000)
            return self._respond(502, b'{"error":"upstream error"}')

        log(agent, name, method, path, "forward", "scoped key injected", status,
            (time.time() - started) * 1000)
        self._respond(status, body)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"broker on {LISTEN[0]}:{LISTEN[1]}", file=sys.stderr)
    ThreadingHTTPServer(LISTEN, Handler).serve_forever()
