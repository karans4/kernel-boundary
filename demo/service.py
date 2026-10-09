"""Local PatchMedic recording API. Fixed actions only; no arbitrary command endpoint."""
import copy
import os
import socket
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
from agent.patcher import patch, validate_candidate, difference
from agent.advisory_triage import MODELS
from semgrep.gate import scan
from demo.workspace import validate, run_job
from demo import accounts
LOCK = threading.RLock()

def initial():
    return dict(status="idle", task="Patch vendored slug_dependency 1.0.0 → 1.0.1",
        stages=[], pipeline=[], semgrep=[], incomingDiff="", diff="", tests=dict(passed=0,total=4,output=""), incidents=[], events=[],
        advisory=(ROOT/"demo/fixtures/advisory.txt").read_text(), reviewReady=False,
        runId=None,error=None, triage=dict(source=None,summary="",model=None,status="idle"),
        mode="four AkashML passes; locally gated generated patch; simulated compromised-agent probes")
STATE = initial()

def update(**values):
    if values.get('status') in ('complete','error','blocked'): values.setdefault('runEndedAt',time.time())
    with LOCK:
        STATE.update(values)
        accounts.save_run(STATE)

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
        code = 'import pathlib; pathlib.Path("/workspace/.secrets/blocked.txt").read_bytes()' if os.environ.get('KB_CONFINED')=='1' else 'import pathlib; pathlib.Path.home().joinpath(".ssh/kb_demo_key").read_bytes()'
        target = '/workspace/.secrets/blocked.txt' if os.environ.get('KB_CONFINED')=='1' else str(Path.home()/".ssh/kb_demo_key")
    else:
        code = 'import socket; s=socket.socket(); s.settimeout(3); s.connect(("203.0.113.77",443))'
        target = "203.0.113.77:443"
    started = time.time()
    confined=os.environ.get("KB_CONFINED")=="1"
    workspace=STATE.get("workspacePath",str(ROOT/"demo/runs"/run_id))
    process = subprocess.Popen([str(ROOT/("bin/kb-agent" if confined else "bin/kb-run")),name,*([workspace] if confined else []),"--","python3","-c",code],
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
            + f"WHERE agent='{name}' AND toUnixTimestamp64Milli(ts)>={int(started*1000)-1000} "
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
        incoming = ROOT/"demo/fixtures/incoming"
        incoming_diff = "".join("--- /dev/null\n+++ b/"+p.name+"\n"+"".join("+"+line+"\n" for line in p.read_text().splitlines()) for p in sorted(incoming.iterdir()))
        update(incomingDiff=incoming_diff)
        stage("Semgrep · incoming update","running","Scan the offered dependency files before applying or running them.")
        rejected=scan(incoming,run_id,"incoming dependency update")
        with LOCK: STATE["semgrep"].append(rejected)
        if rejected["decision"]!="block": raise RuntimeError("Poisoned update unexpectedly passed static gate")
        stage("Semgrep · incoming update","complete",f"Rejected poisoned update: {rejected['count']} findings stored in ClickHouse. Nothing executed.")
        context=dict(advisory=STATE["advisory"],source=(workspace/"slug_dependency.py").read_text(),
            tests=(workspace/"test_dependency.py").read_text(),call_site=(ROOT/"demo/fixtures/application.py").read_text(),
            rejected_incoming_diff=incoming_diff,semgrep_findings=rejected["findings"])
        names={"intake":"Advisory intake / legitimacy","exploitability":"Exploitability","synthesis":"Patch synthesis","review":"Self-review"}
        candidate=None
        for step in ("intake","exploitability","synthesis","review"):
            title="AkashML · "+names[step]
            model=MODELS[step]
            stage(title,"running",model+" via scoped broker /llm; agent carries only a placeholder.")
            with LOCK: STATE["pipeline"].append(dict(step=step,title=names[step],model=model,status="running",summary=""))
            agent_name="antibody-"+run_id[:8]+"-"+step
            for attempt in range(2):
                try:
                    result=subprocess.run([str(ROOT/"bin/kb-run"),agent_name,"--","python3",
                        str(ROOT/"agent/advisory_triage.py"),step,agent_name],input=json.dumps(context),
                        capture_output=True,text=True,timeout=120)
                    if result.returncode: raise RuntimeError("AkashML request or bounded response validation failed")
                    recommendation=json.loads(result.stdout)
                    if step=="synthesis" and recommendation["action"]=="patch":
                        validate_candidate(recommendation["code"])
                    with LOCK: STATE["pipeline"][-1].update(recommendation,attempts=attempt+1)
                    update(triage=recommendation)
                    stage(title,"complete",recommendation["summary"])
                    break
                except Exception as error:
                    if attempt==0:
                        context["validation_feedback"]="The previous response failed bounded validation: "+str(error)[:250]+". Correct it; return the required JSON."
                        with LOCK: STATE["pipeline"][-1].update(attempts=1,summary="First response invalid or unavailable; retrying once. No patch applied.")
                        stage(title,"running","First response invalid or unavailable; retrying once.")
                    else:
                        with LOCK: STATE["pipeline"][-1].update(status="error",attempts=2,summary="Model unavailable or invalid after one retry. No fallback patch is applied.")
                        stage(title,"error","Model unavailable or invalid; patch gate stays closed.")
                        raise
            if recommendation["action"]=="decline" or (step=="exploitability" and not recommendation["reachable"]):
                update(status="declined",error="Model declined this patch; no candidate applied.")
                return
            context[step]=recommendation
            if step=="synthesis":
                candidate=validate_candidate(recommendation["code"])
                diff=difference(context["source"],candidate)
                context["candidate"]=candidate
                context["diff"]=diff
                update(diff=diff)
        stage("Semgrep · generated patch","running","Scan materialized candidate source before application.")
        candidate_dir=workspace/"candidate"
        candidate_dir.mkdir()
        (candidate_dir/"slug_dependency.py").write_text(candidate)
        clean=scan(candidate_dir,run_id,"generated patch")
        with LOCK: STATE["semgrep"].append(clean)
        if clean["decision"]!="pass":
            stage("Semgrep · generated patch","blocked","Candidate rejected; nothing applied.")
            update(status="blocked",error="Semgrep rejected the generated patch.")
            return
        stage("Semgrep · generated patch","complete","Local scan passed; zero findings stored in ClickHouse. This is not proof of safety.")
        stage("Patch dependency","running","Apply the reviewed, bounded, Semgrep-scanned model candidate.")
        diff=patch(workspace,candidate)
        update(diff=diff)
        stage("Patch dependency","complete","Generated version bump and slug fix applied locally.")
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
        review.write_text("# PatchMedic local patch review\n\nDemo dependency fixture; not a real CVE. "
            "AkashML-generated bounded patch; second model review and local Semgrep gate.\n\nTriage source: " + recommendation["source"] + "\n\n" + recommendation["summary"] + "\n\n4/4 tests passed. "
            "Separate compromised-agent simulations produced PID-correlated kernel denials.\n\n"
            "No GitHub request or posting performed.\n\n```diff\n"+diff+"```\n")
        (workspace/"patch.diff").write_text(diff)
        stage("Prepare local review","complete",str(review))
        update(status="complete",reviewReady=True,reviewPath=str(review))
    except Exception as error:
        with LOCK:
            for entry in STATE["stages"]:
                if entry["status"]=="running": entry.update(status="error",detail=str(error))
        update(status="error",error=str(error))

WATCH_FILE = ROOT/'demo/data/watch.json'
WATCH_STATUS = {'status':'not configured','enabled':False}
def configured_job(run_id,job,owner):
    run_job(run_id,job,update,stage,STATE,LOCK,probe)
    if job.get('transient'): return
    with LOCK:
        if STATE.get('commit'):
            WATCH_FILE.parent.mkdir(parents=True,exist_ok=True)
            previous=json.loads(WATCH_FILE.read_text()) if WATCH_FILE.exists() else {}
            saved=dict(owner=owner,job=job,commit=STATE['commit'],lastCheck=time.time(),lastMission=time.time(),publishedDigest=STATE.get('publishedDigest',previous.get('publishedDigest') if previous.get('job',{}).get('repository')==job['repository'] else None),prUrl=STATE.get('prUrl',previous.get('prUrl')))
            WATCH_FILE.write_text(json.dumps(saved))
            WATCH_FILE.chmod(0o600)
            WATCH_STATUS.update(status='watching',enabled=True,mission=job['task'],repository=job['repository'],lastCommit=STATE['commit'],intervalSeconds=300,lastCheck=time.time(),lastChecked=time.time(),nextCheck=time.time()+300)
            update(watch=dict(WATCH_STATUS))
def watch_loop():
    global STATE
    while True:
        time.sleep(300)
        try:
            if not WATCH_FILE.exists(): continue
            watch=json.loads(WATCH_FILE.read_text())
            result=subprocess.run(['git','ls-remote','https://github.com/'+watch['job']['repository']+'.git','HEAD'],capture_output=True,text=True,timeout=30)
            if result.returncode or not result.stdout.strip(): continue
            head=result.stdout.split()[0]
            with LOCK:
                WATCH_STATUS.update(status='watching',enabled=True,mission=watch['job']['task'],repository=watch['job']['repository'],lastCheck=time.time(),lastChecked=time.time(),nextCheck=time.time()+300,lastCommit=head,intervalSeconds=300)
                if STATE['status']=='running': continue
                if head==watch['commit'] and time.time()-watch.get('lastMission',0)<900: continue
                accounts.save_run(STATE)
                STATE=initial();run_id=uuid.uuid4().hex
                STATE.update(status='running',runId=run_id,runStartedAt=time.time(),owner=watch['owner'],workspace=True,task=watch['job']['task'],repository=watch['job']['repository'],trigger='New upstream commit detected' if head!=watch['commit'] else 'Scheduled standing-mission check',watch=dict(WATCH_STATUS))
            configured_job(run_id,watch['job'],watch['owner'])
        except Exception:
            WATCH_STATUS.update(status='check failed; retrying',lastChecked=time.time())

class Handler(BaseHTTPRequestHandler):
    def respond(self,status,body):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(encoded)))
        self.send_header("Cache-Control","no-store")
        self.end_headers()
        self.wfile.write(encoded)
    def token(self):
        header=self.headers.get("Authorization","")
        return header[7:] if header.startswith("Bearer ") else ""
    def do_GET(self):
        if self.path not in ("/api/state","/api/runner"): return self.respond(404,dict(error="not found"))
        user=accounts.authenticate(self.token())
        if not user: return self.respond(401,dict(error="Please sign in"))
        if self.path=="/api/runner":
            ready=os.environ.get("KB_CONFINED")=="1" and Path(os.environ.get("KB_GUARD_READY","/tmp/patchmedic-guard.ready")).exists()
            return self.respond(200,dict(name=socket.gethostname(),platform="Ubuntu",ready=ready,workspaceRoot=os.environ.get("KB_WORKSPACE_ROOT",str(ROOT/"demo/runs"))))
        with LOCK:
            accounts.save_run(STATE)
            snapshot=copy.deepcopy(STATE) if STATE.get("owner")==user["id"] else initial()
        if snapshot.get("runId") and snapshot.get("owner")==user["id"]:
            try:
                prefix=snapshot["runId"][:8]
                names=["workspace-"+prefix+"-"+step for step in ("assessment","review","agent")]+["antibody-"+prefix+"-"+kind for kind in ("open","connect")]
                scope="agent IN ("+",".join("\""+name+"\"" for name in names)+")"
                scope=scope.replace('"',"'")
                records=query("SELECT ts,agent,pid,kind,verdict,mode,path,addr,port FROM kb.events WHERE "+scope+" AND kind IN ('open','connect') ORDER BY ts DESC LIMIT 200 FORMAT JSONEachRow")
                totals=query("SELECT verdict,count() AS count FROM kb.events WHERE "+scope+" AND kind IN ('open','connect') GROUP BY verdict FORMAT JSONEachRow")
                http=query("SELECT ts,route,method,target,status,latency_ms FROM kb.broker WHERE "+scope+" ORDER BY ts DESC LIMIT 100 FORMAT JSONEachRow")
                snapshot["httpEvents"]=[dict(timestamp=r["ts"],method=r["method"],path=r["target"],status=r["status"],durationMs=r["latency_ms"],source="Daemon-reported upstream HTTPS",route=r["route"]) for r in http]
                httpfile=Path.home()/'.local/state/patchmedic/http.jsonl'
                if httpfile.exists() and snapshot.get('runStartedAt'):
                    local=[]
                    for line in httpfile.read_text().splitlines()[-2000:]:
                        try: record=json.loads(line)
                        except ValueError: continue
                        if snapshot['runStartedAt']<=record.get('observed_at',0)<=snapshot.get('runEndedAt',time.time()):
                            record['timestamp']=record['observed_at'];local.append(record)
                    paired=[];pending={}
                    for record in local:
                        if record.get('method'):
                            pending[(record.get('sport'),record.get('dport'))]=record;paired.append(record)
                        elif record.get('status'):
                            request=pending.get((record.get('dport'),record.get('sport')))
                            if request:
                                request['status']=record['status'];request['durationMs']=round((record['observed_at']-request['observed_at'])*1000,2)
                    snapshot['httpEvents']=paired[-100:]+snapshot.get('httpEvents',[])
                snapshot.update(events=records,accessCounts={x["verdict"]:int(x["count"]) for x in totals},feedStatus="live")
                if snapshot["status"]!="running": accounts.save_run(snapshot)
            except Exception: snapshot.update(feedStatus="unavailable")
        snapshot.update(user=user,history=accounts.history(user["id"]))
        if WATCH_FILE.exists():
            watch=json.loads(WATCH_FILE.read_text())
            if watch.get("owner")==user["id"]: snapshot["watch"]=dict(WATCH_STATUS)
        self.respond(200,snapshot)
    def do_POST(self):
        global STATE
        allowed=("/api/run","/api/reset","/api/workspace","/api/signup","/api/login","/api/logout","/api/settings")
        if self.path not in allowed: return self.respond(404,dict(error="not found"))
        try:
            length=int(self.headers.get("Content-Length","0"))
            if length<0: return self.respond(400,dict(error="invalid content length"))
            if length>4096: return self.respond(413,dict(error="body too large"))
            payload=json.loads(self.rfile.read(length) or b"{}")
            if self.path=="/api/signup": return self.respond(201,accounts.register(payload))
            if self.path=="/api/login": return self.respond(200,accounts.login(payload))
            user=accounts.authenticate(self.token())
            if not user: return self.respond(401,dict(error="Please sign in"))
            if self.path=="/api/logout":
                accounts.logout(self.token()); return self.respond(200,dict(ok=True))
            if self.path=="/api/settings":
                if not isinstance(payload,dict) or set(payload)!={"workspace"}: raise ValueError("Invalid settings")
                accounts.rename(user["id"],payload["workspace"]);return self.respond(200,dict(ok=True))
            if self.path=="/api/workspace":
                if os.environ.get("KB_CONFINED")=="1" and not Path(os.environ.get("KB_GUARD_READY","/tmp/patchmedic-guard.ready")).exists(): return self.respond(503,dict(error="Runner boundary is not armed"))
                payload=validate(payload)
            elif payload != {}: return self.respond(400,dict(error="only an empty JSON object is accepted"))
        except (ValueError,json.JSONDecodeError) as error: return self.respond(400,dict(error=str(error)))
        with LOCK:
            if STATE["status"]=="running": return self.respond(409,dict(error="This runner is busy. Try again when its current task finishes."))
            accounts.save_run(STATE)
            STATE=initial()
            if self.path=="/api/reset": return self.respond(200,STATE)
            run_id=uuid.uuid4().hex
            STATE.update(status="running",runId=run_id,owner=user["id"],runStartedAt=time.time())
            if self.path=="/api/workspace":
                STATE.update(task=payload["task"],repository=payload["repository"],workspace=True)
                threading.Thread(target=configured_job,args=(run_id,payload,user["id"]),daemon=True).start()
            else: threading.Thread(target=run,args=(run_id,),daemon=True).start()
            self.respond(202,STATE)
    def log_message(self,*args): pass

if __name__=="__main__":
    if WATCH_FILE.exists():
        watch=json.loads(WATCH_FILE.read_text())
        saved=accounts.history(watch["owner"])
        if saved: STATE=saved[0]
        WATCH_STATUS.update(status='watching',enabled=True,mission=watch['job']['task'],repository=watch['job']['repository'],lastCommit=watch['commit'],intervalSeconds=300,nextCheck=time.time()+300,lastCheck=watch.get('lastCheck'))
    threading.Thread(target=watch_loop,daemon=True).start()
    print("PatchMedic backend on http://127.0.0.1:8091",flush=True)
    ThreadingHTTPServer(("127.0.0.1",8091),Handler).serve_forever()
