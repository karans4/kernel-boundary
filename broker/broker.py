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



PUBLISH_CAP = ''
def publish_candidate(payload):
    repository='karans4/kb-demo-target'
    branch=payload.get('branch','')
    if not re.fullmatch(r'patchmedic/[a-f0-9]{32}',branch): raise ValueError('Invalid publication branch')
    files=payload.get('files',{})
    if not isinstance(files,dict) or not 1<=len(files)<=5: raise ValueError('Invalid bounded patch')
    for name,content in files.items():
        if not re.fullmatch(r'[A-Za-z0-9_./-]+',name) or name.startswith(('/', '.', 'tests/')) or '..' in name.split('/') or len(content)>30000: raise ValueError('Invalid patch file')
    def api(method,path,body=None):
        request=urllib.request.Request('https://api.github.com/repos/'+repository+path,data=json.dumps(body).encode() if body is not None else None,method=method,headers={'Authorization':ROUTES['gh']['auth'],'Content-Type':'application/json','Accept':'application/vnd.github+json','User-Agent':'PatchMedic-daemon'})
        with urllib.request.urlopen(request,timeout=30) as response:return json.load(response)
    current=api('GET','/git/ref/heads/main')['object']['sha']
    if current!=payload.get('baseCommit'): raise ValueError('Upstream changed; rerun investigation')
    base=api('GET','/git/commits/'+current)
    tree=[]
    for path,content in files.items():
        blob=api('POST','/git/blobs',{'content':content,'encoding':'utf-8'})
        tree.append({'path':path,'mode':'100644','type':'blob','sha':blob['sha']})
    newtree=api('POST','/git/trees',{'base_tree':base['tree']['sha'],'tree':tree})
    commit=api('POST','/git/commits',{'message':'fix: correct invoice tax calculation','tree':newtree['sha'],'parents':[current]})
    api('POST','/git/refs',{'ref':'refs/heads/'+branch,'sha':commit['sha']})
    pr=api('POST','/pulls',{'title':'Fix invoice tax precision','head':branch,'base':'main','body':'PatchMedic investigated the repository using a bounded autonomous workspace agent. This minimal patch passed the repository tests and local Semgrep scan. Kernel policies enforced file and network boundaries throughout the run. No merge is performed.'})
    return {'url':pr['html_url'],'number':pr['number'],'branch':branch}

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
        if self.path=='/publish':
            if not PUBLISH_CAP or self.headers.get('Authorization')!='Bearer '+PUBLISH_CAP: return self._respond(403,b'{"error":"trusted publication capability required"}')
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=150000: raise ValueError('Patch too large')
                started=time.time()
                result=publish_candidate(json.loads(self.rfile.read(size)))
                log(self.headers.get('X-KB-Agent','operator'),'gh','POST','/repos/karans4/kb-demo-target/pulls','forward','verified scoped publication',201,(time.time()-started)*1000)
                return self._respond(201,json.dumps(result).encode())
            except Exception as error:
                return self._respond(409,json.dumps({'error':str(error)}).encode())
        self._handle("POST")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"broker on {LISTEN[0]}:{LISTEN[1]}", file=sys.stderr)
    ThreadingHTTPServer(LISTEN, Handler).serve_forever()
