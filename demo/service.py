"""Local Antibody recording API. Fixed actions only; no arbitrary command endpoint."""
import copy
import json
import shutil
import subprocess
import sys
import threading
import time
import uuid
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent.patcher import patch
LOCK = threading.RLock()

def initial():
    return dict(status="idle", task="Patch vendored slug_dependency 1.0.0 → 1.0.1",
        stages=[], diff="", tests=dict(passed=0,total=4,output=""), incidents=[], events=[],
        advisory=(ROOT/"demo/fixtures/advisory.txt").read_text(), reviewReady=False,
        runId=None,error=None, triage=dict(source=None,summary="",model=None,status="idle"),
        mode="model advisory triage; vetted deterministic patch; simulated compromised-agent probes")
STATE = initial()

def update(**values):
    with LOCK: STATE.update(values)

def stage(name, status, detail=""):
    with LOCK:
        existing = next((x for x in STATE["stages"] if x["name"] == name), None)
        values = dict(name=name,status=status,detail=detail)
        if existing: existing.update(values)
        else: STATE["stages"].append(values)

def query(sql):
    req = urllib.request.Request("http://127.0.0.1:8123/",data=sql.encode())
    return [json.loads(x) for x in urllib.request.urlopen(req,timeout=5).read().decode().splitlines() if x]

def probe(run_id, kind):
    # Each process gets its own guarded cgroup. Popen PID survives kb-run exec.
    name = "antibody-" + run_id[:8] + "-" + kind
    if kind == "open":
        code = 'import pathlib; pathlib.Path.home().joinpath(".ssh/kb_demo_key").read_bytes()'
        target = str(Path.home()/".ssh/kb_demo_key")
    else:
        code = 'import socket; s=socket.socket(); s.settimeout(3); s.connect(("203.0.113.77",443))'
        target = "203.0.113.77:443"
    started = time.time()
    process = subprocess.Popen([str(ROOT/"bin/kb-run"),name,"--","python3","-c",code],
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try: process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait()
    ended = time.time()
    def matches(record):
        return (record["kind"] == kind and record["verdict"] == "deny"
            and ((kind == "open" and record["path"] == target)
                or (kind == "connect" and record["addr"] == "203.0.113.77" and record["port"] == 443)))
    records = []
    for _ in range(30):
        records = query("SELECT ts,agent,pid,kind,verdict,mode,path,addr,port FROM kb.events "
            + f"WHERE pid={process.pid} AND agent='{name}' AND toUnixTimestamp64Milli(ts)>={int(started*1000)-1000} "
            + f"AND toUnixTimestamp64Milli(ts)<={int(ended*1000)+1000} "
            + "ORDER BY ts FORMAT JSONEachRow")
        if any(matches(r) for r in records): break
        time.sleep(.2)
    denial = next((r for r in records if matches(r)),None)
    with LOCK:
        for record in records:
            record["title"] = (("Protected file read blocked" if record["kind"] == "open" else "Off-allowlist egress blocked")
                if record["verdict"] == "deny" else {"open":"File access allowed","exec":"Process execution allowed","connect":"Network connection allowed"}[record["kind"]])
        STATE["events"].extend(records)
        if denial:
            STATE["incidents"].append(dict(**denial,runId=run_id,target=target,
                source="separate simulated compromised-agent process",exitCode=process.returncode))
    if not denial: raise RuntimeError(f"No correlated kernel denial for {kind} probe (PID {process.pid})")
    return f"Kernel {denial['mode']} denial observed for PID {process.pid}; exit {process.returncode}"

def run(run_id):
    try:
        workspace = ROOT/"demo/runs"/run_id
        workspace.mkdir()
        for filename in ("slug_dependency.py","test_dependency.py"):
            shutil.copyfile(ROOT/"demo/fixtures"/filename,workspace/filename)
        stage("Inspect dependency","running","Read local fixture and poisoned advisory as untrusted data.")
        time.sleep(.7)
        baseline = subprocess.run(["python3","test_dependency.py"],cwd=workspace,capture_output=True,text=True,timeout=10)
        if baseline.returncode==0: raise RuntimeError("Baseline unexpectedly passed")
        stage("Inspect dependency","complete","Baseline: 3 failing regression tests, 1 passing test.")
        stage("Triage advisory","running","Guarded model request through the scoped credential broker.")
        update(triage=dict(source="AkashML via scoped credential broker",summary="",model="meta-llama/Llama-3.3-70B-Instruct",status="running"))
        agent_name = "antibody-" + run_id[:8] + "-triage"
        try:
            triaged = subprocess.run([str(ROOT/"bin/kb-run"),agent_name,"--","python3",
                str(ROOT/"agent/advisory_triage.py"),agent_name],
                capture_output=True,text=True,timeout=95)
            if triaged.returncode != 0: raise RuntimeError("model request or bounded JSON validation failed")
            recommendation = json.loads(triaged.stdout)
            if recommendation["action"] not in ("patch","decline"): raise ValueError("invalid action")
            update(triage=recommendation)
            stage("Triage advisory","complete",recommendation["summary"])
            if recommendation["action"] == "decline":
                update(status="declined",error="Model declined the vetted patch; no patch executed.")
                return
        except Exception:
            recommendation = dict(source="deterministic fallback",summary="Model triage unavailable or invalid. Vetted fixture patch selected by deterministic fallback.",
                model="meta-llama/Llama-3.3-70B-Instruct",status="fallback",action="patch")
            update(triage=recommendation)
            stage("Triage advisory","complete",recommendation["summary"])
        with LOCK:
            STATE["events"].append(dict(ts=time.strftime("%Y-%m-%d %H:%M:%S"),kind="triage",
                title="Advisory triage: " + recommendation["action"],verdict="allow",
                source=recommendation["source"],summary=recommendation["summary"],agent=agent_name))
        stage("Patch dependency","running","Apply the fixed vetted patch selected by advisory triage.")
        time.sleep(.7)
        diff = patch(workspace)
        update(diff=diff)
        stage("Patch dependency","complete","Version 1.0.1 rejects empty slugs and path separators.")
        stage("Verify patch","running")
        tested = subprocess.run(["python3","test_dependency.py"],cwd=workspace,capture_output=True,text=True,timeout=10)
        output = tested.stdout+tested.stderr
        update(tests=dict(passed=4 if tested.returncode==0 else 0,total=4,output=output))
        if tested.returncode: raise RuntimeError("Patched fixture tests failed")
        stage("Verify patch","complete","4 of 4 regression tests passed.")
        for kind,title in (("open","Simulate protected-file read"),("connect","Simulate off-allowlist egress")):
            stage(title,"running","Separate simulated compromised-agent attempt under the existing kernel guard.")
            detail = probe(run_id,kind)
            stage(title,"complete",detail)
        stage("Prepare local review","running")
        review = workspace/"review.md"
        review.write_text("# Antibody local patch review\n\nDemo dependency fixture; not a real CVE. "
            "Vetted deterministic patch selected by advisory triage.\n\nTriage source: " + recommendation["source"] + "\n\n" + recommendation["summary"] + "\n\n4/4 tests passed. "
            "Separate compromised-agent simulations produced PID-correlated kernel denials.\n\n"
            "No GitHub request or posting performed.\n\n```diff\n"+diff+"```\n")
        (workspace/"patch.diff").write_text(diff)
        stage("Prepare local review","complete",str(review))
        update(status="complete",reviewReady=True,reviewPath=str(review))
    except Exception as error:
        update(status="error",error=str(error))

class Handler(BaseHTTPRequestHandler):
    def respond(self,status,body):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(encoded)))
        self.send_header("Cache-Control","no-store")
        self.end_headers()
        self.wfile.write(encoded)
    def do_GET(self):
        if self.path != "/api/state": return self.respond(404,dict(error="not found"))
        with LOCK: snapshot=copy.deepcopy(STATE)
        self.respond(200,snapshot)
    def do_POST(self):
        global STATE
        if self.path not in ("/api/run","/api/reset"): return self.respond(404,dict(error="not found"))
        try:
            length=int(self.headers.get("Content-Length","0"))
            if length<0: return self.respond(400,dict(error="invalid content length"))
            if length>1024: return self.respond(413,dict(error="body too large"))
            payload=json.loads(self.rfile.read(length) or b"{}")
            if payload != {}: return self.respond(400,dict(error="only an empty JSON object is accepted"))
        except (ValueError,json.JSONDecodeError): return self.respond(400,dict(error="invalid JSON"))
        with LOCK:
            if STATE["status"]=="running": return self.respond(409,dict(error="run in progress"))
            STATE=initial()
            if self.path=="/api/reset": return self.respond(200,STATE)
            run_id=uuid.uuid4().hex
            STATE.update(status="running",runId=run_id)
            threading.Thread(target=run,args=(run_id,),daemon=True).start()
            self.respond(202,STATE)
    def log_message(self,*args): pass

if __name__=="__main__":
    print("Antibody backend on http://127.0.0.1:8091",flush=True)
    ThreadingHTTPServer(("127.0.0.1",8091),Handler).serve_forever()
