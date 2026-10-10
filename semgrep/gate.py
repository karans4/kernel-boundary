"""Local Semgrep CE gate. Scan complete candidate files, never raw diff syntax."""
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BINARY=Path.home()/'.local/share/antibody-semgrep/bin/semgrep'
SCHEMA='''CREATE TABLE IF NOT EXISTS kb.semgrep (
 ts DateTime64(6), run_id String, scan_id String, artifact String,
 decision LowCardinality(String), rule_id String, severity LowCardinality(String),
 path String, line UInt32, message String, findings UInt32, scanner_version String
) ENGINE=MergeTree ORDER BY (run_id, ts)'''

def post(sql, data=None):
    url='http://127.0.0.1:8123/'
    payload=sql.encode() if data is None else (sql+'\n'+json.dumps(data)).encode()
    with urllib.request.urlopen(urllib.request.Request(url,data=payload),timeout=10) as response: response.read()

def scan(target,run_id,artifact,config=None):
    if not BINARY.is_file(): raise RuntimeError('Semgrep CLI missing. Run bin/kb-semgrep-setup.')
    env=dict(os.environ,SEMGREP_SEND_METRICS='off',SEMGREP_ENABLE_VERSION_CHECK='0')
    result=subprocess.run([str(BINARY),'scan','--oss-only','--config',str(config or ROOT/'semgrep/rules.yml'),
        '--metrics=off','--no-git-ignore','--disable-version-check','--json','--quiet','--strict',str(target)],
        capture_output=True,text=True,timeout=60,env=env)
    if result.returncode: raise RuntimeError('Semgrep scan failed; patch gate remains closed')
    parsed=json.loads(result.stdout)
    if parsed.get('errors'): raise RuntimeError('Semgrep returned scan errors; patch gate remains closed')
    paths=parsed.get('paths',{}).get('scanned',[])
    if not paths: raise RuntimeError('Semgrep scanned no files; patch gate remains closed')
    findings=[dict(rule_id=x['check_id'],severity=x['extra']['severity'],path=str(Path(x['path']).relative_to(target)),
        line=x['start']['line'],message=x['extra']['message']) for x in parsed.get('results',[])]
    for finding in findings:
        source=(Path(target)/finding['path']).resolve()
        if source.is_relative_to(Path(target).resolve()) and source.is_file():
            lines=source.read_text(errors='replace').splitlines()
            start=max(0,finding['line']-3);end=min(len(lines),finding['line']+3)
            finding['code']='\n'.join(f'{i+1}: {lines[i]}' for i in range(start,end))[:4000]
    report=dict(artifact=artifact,decision='block' if findings else 'pass',findings=findings,
        count=len(findings),files=len(paths),version=parsed.get('version','unknown'),
        engine='Semgrep OSS / local rules / metrics off',stored=False)
    post(SCHEMA)
    base=dict(ts=f'{time.time():.6f}',run_id=run_id,scan_id=artifact,artifact=artifact,
        decision=report['decision'],findings=len(findings),scanner_version=report['version'])
    # A summary row records successful zero-finding scans as well as rejected scans.
    post('INSERT INTO kb.semgrep FORMAT JSONEachRow',dict(**base,rule_id='',severity='',path='',line=0,message='Scan completed'))
    for finding in findings: post('INSERT INTO kb.semgrep FORMAT JSONEachRow',dict(**base,**{k:v for k,v in finding.items() if k!='code'}))
    report['stored']=True
    return report
