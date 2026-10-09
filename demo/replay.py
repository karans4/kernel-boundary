"""Advisory-inspired, explicitly authorized harmless malicious-update replay."""
import json,os,subprocess,time,urllib.request
from pathlib import Path
from semgrep.gate import scan
ROOT=Path(__file__).resolve().parents[1]

def run_replay(run_id,job,out,update,stage,state,lock):
    update(replay=True,blockedCandidate=True,workspacePath=str(out),repository=job['repository'],mode='Advisory-inspired synthetic malicious-update replay; never applied or published',diff='',prUrl=None,reviewReady=False)
    stage('Verify historical advisory','running','Fetch authoritative OSV record; repository is replay context, not a claim it was affected')
    advisory_id='GHSA-97m3-w2cp-4xx6'
    url='https://api.osv.dev/v1/vulns/'+advisory_id
    with urllib.request.urlopen(url,timeout=25) as response: advisory=json.load(response)
    if advisory.get('id')!=advisory_id: raise RuntimeError('Unexpected advisory source')
    sources=[dict(title=advisory_id+' · OSV',url='https://osv.dev/vulnerability/'+advisory_id),dict(title='GitHub advisory',url='https://github.com/advisories/'+advisory_id)]
    published=advisory.get('published','unknown')
    update(sources=sources,advisory=advisory.get('summary',advisory_id),advisories=[dict(id=advisory_id,published=published,summary=advisory.get('summary',''))])
    stage('Verify historical advisory','complete','node-ipc incident: malicious file overwriting; published '+published+'. Replay below uses a different, harmless synthetic canary-read payload.')
    candidate=out/'incoming-update';candidate.mkdir()
    (candidate/'package.json').write_text(json.dumps({'name':'patchmedic-synthetic-replay','version':'0.0.0-demo','scripts':{'postinstall':'python3 postinstall.py'}},indent=2))
    (candidate/'postinstall.py').write_text("# Harmless synthetic test: this mount contains no real secret.\nprint('Synthetic postinstall attempting protected canary access', flush=True)\nopen('/workspace/.secrets/blocked.txt').read()\n")
    update(incomingDiff="Synthetic package postinstall:\n"+(candidate/'postinstall.py').read_text())
    stage('Semgrep · incoming update','running','Scan complete incoming files before any application or execution')
    result=scan(candidate,run_id,'synthetic incoming dependency update')
    with lock: state['semgrep'].append(result)
    if result['decision']!='block': raise RuntimeError('Synthetic malicious update unexpectedly passed static gate')
    stage('Semgrep · incoming update','blocked',str(result['count'])+' findings recorded in ClickHouse; candidate was not applied')
    stage('Runtime boundary replay','running','Explicit operator-authorized replay of harmless blocked fixture; no dependency installation or real secret')
    name='workspace-'+run_id[:8]+'-agent';started=time.time()
    process=subprocess.run([str(ROOT/'bin/kb-agent'),name,str(out),'--','python3','/workspace/incoming-update/postinstall.py'],capture_output=True,text=True,timeout=15)
    denial=None
    for _ in range(25):
        sql="SELECT ts,agent,pid,kind,verdict,mode,path,addr,port FROM kb.events WHERE agent='"+name+"' AND kind='open' AND verdict='deny' AND path='/workspace/.secrets/blocked.txt' AND toUnixTimestamp64Milli(ts)>="+str(int(started*1000)-1000)+" ORDER BY ts DESC LIMIT 1 FORMAT JSONEachRow"
        with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8123/',data=sql.encode()),timeout=5) as response:
            rows=response.read().decode().splitlines()
        if rows: denial=json.loads(rows[0]);break
        time.sleep(.2)
    if not denial: raise RuntimeError('No correlated kernel denial; replay is not verified')
    with lock:
        state['incidents'].append(dict(**denial,runId=run_id,target=denial['path'],source='explicit synthetic dependency postinstall replay',exitCode=process.returncode))
        state['events'].append(denial)
    stage('Runtime boundary replay','blocked','Actual postinstall process PID '+str(denial['pid'])+' killed by kernel policy; exit '+str(process.returncode))
    stage('Publication','blocked','Never applied, never published. Historical advisory and synthetic payload are distinct.')
    report=dict(advisory=advisory_id,published=published,source=url,synthetic=True,historicalBehavior='node-ipc malicious file overwriting',replayBehavior='harmless protected canary read',semgrepFindings=result['count'],kernelDenial=denial,exitCode=process.returncode,publishedToGitHub=False,applied=False)
    (out/'replay-report.json').write_text(json.dumps(report,indent=2))
    update(status='blocked',report=json.dumps(report,indent=2),triage=dict(summary='Static gate rejected the update; an explicit harmless runtime replay was stopped by the kernel.',source='OSV advisory + actual Semgrep and eBPF evidence'),blockedCandidate=True,replay=True,reviewReady=False)
