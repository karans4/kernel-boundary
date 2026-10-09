"""Bounded public GitHub inspection: source is data, never executed."""
import base64,json,re,subprocess,urllib.request,os,hashlib
from pathlib import Path
from semgrep.gate import scan
ROOT=Path(__file__).resolve().parents[1]

def validate(payload):
    if not isinstance(payload,dict) or set(payload)-{'repository','task','boundaryTests','transient'}: raise ValueError('Expected repository, task and boundaryTests')
    repo=payload.get('repository','').strip()
    match=re.fullmatch(r'(?:https://github\.com/)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?',repo)
    if not match or any(x in ('.','..') for x in match[1].split('/')): raise ValueError('Enter a public GitHub owner/repository URL')
    task=payload.get('task','').strip()
    if not 10<=len(task)<=1500: raise ValueError('Describe the task in 10–1500 characters')
    if not isinstance(payload.get('boundaryTests',False),bool): raise ValueError('Invalid boundary test option')
    if not isinstance(payload.get('transient',False),bool): raise ValueError('Invalid transient task')
    return dict(repository=match[1],task=task,boundaryTests=payload.get('boundaryTests',False),transient=payload.get('transient',False))

def get(path):
    req=urllib.request.Request('https://api.github.com/'+path,headers={'User-Agent':'PatchMedic','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(req,timeout=25) as response: return json.load(response)

def run_job(run_id,job,update,stage,state,lock,probe):
    try:
        out=Path(os.environ.get('KB_WORKSPACE_ROOT', str(ROOT/'demo/runs')))/state.get('owner','local')/run_id;out.mkdir(parents=True)
        stage('Fetch public repository','running',job['repository']+' · read-only Git fetch; no installation or script execution')
        gitdir=out/"repository.git"
        fetched=subprocess.run(["git","-c","core.hooksPath=/dev/null","clone","--bare","--depth=1","--filter=blob:none","https://github.com/"+job["repository"]+".git",str(gitdir)],capture_output=True,text=True,timeout=60)
        if fetched.returncode: raise RuntimeError("Unable to fetch public repository. Check the URL and network access.")
        commit=subprocess.check_output(["git","--git-dir",str(gitdir),"rev-parse","HEAD"],text=True).strip()
        names=subprocess.check_output(["git","--git-dir",str(gitdir),"ls-tree","-r","--name-only","-z","HEAD"],timeout=30).decode().split("\0")
        paths=[dict(path=name) for name in names if name and (Path(name).suffix in (".py",".js",".ts",".json",".md",".yml",".yaml") or name=="Dockerfile")]
        paths.sort(key=lambda x:(x["path"] not in ("package.json","requirements.txt","README.md","pyproject.toml"),len(x["path"])))
        selected=paths[:16];source=[];checkout=out/"source";checkout.mkdir()
        for item in selected:
            content=subprocess.check_output(["git","--git-dir",str(gitdir),"show",commit+":"+item["path"]],timeout=30).decode("utf-8",errors="replace")[:20000]
            relative=Path(item["path"])
            if relative.is_absolute() or ".." in relative.parts: continue
            target=checkout/relative;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_text(content)
            source.append(dict(path=item["path"],content=content[:8000]))
        sources=[dict(title=job['repository'],url='https://github.com/'+job['repository']+'/tree/'+commit)]
        update(workspacePath=str(out),repository=job['repository'],commit=commit,sources=sources,advisory='Public source pinned to '+commit,coverage=dict(files=len(selected),eligible=len(paths),truncated=len(paths)>16),mode='Bounded public-source review; repository code is not executed',tests=dict(output='Repository tests not run. Dependencies and scripts are not executed.',passed=0,total=0))
        stage('Fetch public repository','complete',f'{len(selected)} files sampled from {len(paths)} eligible files; pinned commit {commit[:12]}')
        stage('Semgrep · repository source','running','Local static scan of fetched source; findings do not establish exploitability')
        result=scan(checkout,run_id,'public repository source')
        with lock: state['semgrep'].append(result)
        stage('Semgrep · repository source','complete',str(result['count'])+' findings stored in ClickHouse')
        advisories=[]
        manifest=next((x for x in source if x['path']=='package.json'),None)
        if manifest:
            try: package=json.loads(manifest['content'])
            except ValueError: package={}
            for name,version in list({**package.get('dependencies',{}),**package.get('devDependencies',{})}.items())[:8]:
                if not isinstance(version,str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?',version): continue
                req=urllib.request.Request('https://api.osv.dev/v1/query',data=json.dumps({'package':{'name':name,'ecosystem':'npm'},'version':version}).encode(),headers={'Content-Type':'application/json'})
                with urllib.request.urlopen(req,timeout=25) as response: found=json.load(response)
                for finding in found.get('vulns',[])[:5]:
                    advisories.append(dict(package=name,version=version,id=finding['id'],summary=finding.get('summary','')))
                    sources.append(dict(title=finding['id'],url='https://osv.dev/vulnerability/'+finding['id']))
        update(sources=sources,advisories=advisories)
        context=dict(task=job['task'],repository=job['repository'],commit=commit,source=source,advisories=advisories,semgrep=result['findings'],scope='Sampled source only; exact npm versions only, up to 8 direct dependencies. No installation, execution, complete audit, publishing or writes to upstream. Cite only supplied sources.')
        stage('AkashML · autonomous agent','running','Model chooses workspace tools; yeet enforces every process action')
        with lock: state['pipeline'].append(dict(step='autonomous',title='Autonomous investigation and repair',model='openai/gpt-oss-120b',status='running',summary=''))
        name='workspace-'+run_id[:8]+'-agent'
        worker=(ROOT/'agent/autonomous.py').read_text()
        payload=dict(task=job['task'],repository=job['repository'],commit=commit,advisories=advisories,semgrep=result['findings'],agent=name)
        process=subprocess.Popen([str(ROOT/'bin/kb-agent'),name,str(out),'--','python3','-c',worker],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        process.stdin.write(json.dumps(payload));process.stdin.close()
        answer=None; activities=[]
        for line in process.stdout:
            item=json.loads(line);activities.append(item)
            update(toolActivity=activities)
            if item['kind']=='tool': stage('Agent · '+str(item['round'])+' · '+item['action'],'complete',json.dumps(item.get('arguments',{})))
            elif item['kind']=='validation':
                output=json.dumps(item['results'],indent=2); match=re.search(r'(\d+) passed',output); count=int(match[1]) if match else 0
                update(tests=dict(passed=count if item['passed'] else 0,total=count or 1,output=output))
            elif item['kind']=='result': answer=item
        if process.wait(timeout=5) or not answer: raise RuntimeError('Autonomous guarded worker failed: '+process.stderr.read()[-350:])
        summary=answer['summary']
        if answer['diff']:
            stage('Semgrep · generated patch','running','Scan updated workspace before publication')
            patched=scan(checkout,run_id,'autonomous generated patch')
            with lock: state['semgrep'].append(patched)
            stage('Semgrep · generated patch','complete',str(patched['count'])+' findings; '+patched['decision'])
            answer['staticPassed']=patched['decision']=='pass'
        with lock: state['pipeline'][-1].update(status='complete',summary=summary)
        stage('AkashML · autonomous agent','complete',summary)
        update(report=json.dumps(answer,indent=2),diff=answer['diff'],triage=dict(summary=summary,source='AkashML tool-directed investigation'),mode='Autonomous bounded workspace investigation, repair and validation; kernel-enforced tools',publishReady=bool(answer['diff'] and answer['validated'] and answer.get('staticPassed')))
        digest=hashlib.sha256((commit+answer['diff']).encode()).hexdigest()
        watchfile=ROOT/'demo/data/watch.json'
        previous=json.loads(watchfile.read_text()) if watchfile.exists() else {}
        already_published=bool(previous.get('prUrl') and previous.get('commit')==commit and previous.get('job',{}).get('repository')==job['repository'] and previous.get('job',{}).get('task')==job['task'])
        if already_published:
            update(prUrl=previous.get('prUrl'),publishedDigest=digest)
            stage('Publish GitHub pull request','complete','Existing verified repair PR covers this mission at this commit; no duplicate PR')
        if not already_published and job['repository']=='karans4/kb-demo-target' and answer['diff'] and answer['validated'] and answer.get('staticPassed') and os.environ.get('KB_PUBLISH_CAP'):
            stage('Publish GitHub pull request','running','Trusted daemon publishes verified patch to authorized repository only')
            files={name:(checkout/name).read_text() for name in answer['changed']}
            publication=dict(branch='patchmedic/'+run_id,baseCommit=commit,files=files)
            request=urllib.request.Request('http://127.0.0.1:8899/publish',data=json.dumps(publication).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+os.environ['KB_PUBLISH_CAP'],'X-KB-Agent':name})
            try:
                with urllib.request.urlopen(request,timeout=120) as response: published=json.load(response)
                update(pullRequest=published,prUrl=published['url'],publishedDigest=digest)
                stage('Publish GitHub pull request','complete',published['url'])
            except Exception:
                stage('Publish GitHub pull request','blocked','Publication unavailable; verified patch retained locally')
        if job['boundaryTests']:
            for kind,title in [('open','Simulate protected-file read'),('connect','Simulate off-allowlist egress')]:
                stage(title,'running','Explicit independent attack probe; not evidence the model was fooled')
                stage(title,'complete',probe(run_id,kind))
        (out/'review.json').write_text(json.dumps(dict(job=job,commit=commit,sources=sources,review=answer),indent=2))
        stage('Prepare local review','complete','Agent result saved locally; publication requires passing validation and static gate')
        update(status='complete',reviewReady=True,reviewPath=str(out/'review.json'))
    except Exception as error:

        with lock:
            for entry in state['stages']:
                if entry['status']=='running': entry.update(status='error',detail=str(error))
        stage('Workspace run','error',str(error));update(status='error',error=str(error))
