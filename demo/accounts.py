"""Local account store. Session tokens are random; only their hashes are persisted."""
import hashlib,hmac,json,os,re,secrets,sqlite3,time,threading
from pathlib import Path
from contextlib import contextmanager
ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'demo/data';DATA.mkdir(mode=0o700,exist_ok=True)
DB=DATA/'accounts.sqlite3'
LOCK=threading.RLock();ATTEMPTS={}
@contextmanager
def db():
    con=sqlite3.connect(DB,timeout=10)
    con.row_factory=sqlite3.Row
    con.executescript('CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE,salt BLOB,password BLOB,workspace TEXT); CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,user_id TEXT,expires REAL); CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,user_id TEXT,created REAL,snapshot TEXT);')
    os.chmod(DB,0o600)
    try:
        with con: yield con
    finally: con.close()

def rate(email):
    now=time.time()
    with LOCK:
        recent=[x for x in ATTEMPTS.get(email,[]) if x>now-60]
        if len(recent)>=5: raise ValueError('Too many attempts. Try again in a minute.')
        ATTEMPTS[email]=recent+[now]
        if len(ATTEMPTS)>10000: ATTEMPTS.clear()

def credentials(payload):
    if not isinstance(payload,dict) or set(payload)-{'email','password','workspace'}: raise ValueError('Invalid account details')
    email=str(payload.get('email','')).strip().lower();password=payload.get('password','')
    if len(email)>254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email): raise ValueError('Enter a valid email address')
    if not isinstance(password,str) or not 12<=len(password)<=128: raise ValueError('Use a password of 12–128 characters')
    rate(email);return email,password

def derive(password,salt): return hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1)
def session(con,user):
    token=secrets.token_urlsafe(32)
    con.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
    con.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),user['id'],time.time()+86400));con.commit()
    return dict(token=token,user=dict(id=user['id'],email=user['email'],workspace=user['workspace']))
def register(payload):
    email,password=credentials(payload)
    workspace=str(payload.get('workspace','My workspace')).strip()
    if not 1<=len(workspace)<=80: raise ValueError('Workspace name must be 1–80 characters')
    salt=secrets.token_bytes(16);digest=derive(password,salt)
    with db() as con:
        try: con.execute('INSERT INTO users VALUES(?,?,?,?,?)',(secrets.token_hex(16),email,salt,digest,workspace))
        except sqlite3.IntegrityError: raise ValueError('Unable to create account. Sign in or choose another email.')
        user=con.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        return session(con,user)
def login(payload):
    email,password=credentials(payload)
    with db() as con:
        user=con.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        expected=derive(password,user['salt'] if user else bytes(16))
        if not user or not hmac.compare_digest(expected,user['password']): raise ValueError('Email or password is incorrect')
        return session(con,user)
def authenticate(token):
    if not isinstance(token,str) or len(token)>128: return None
    with db() as con:
        user=con.execute('SELECT u.id,u.email,u.workspace FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.hash=? AND s.expires>?',(hashlib.sha256(token.encode()).hexdigest(),time.time())).fetchone()
        return dict(user) if user else None
def logout(token):
    with db() as con: con.execute('DELETE FROM sessions WHERE hash=?',(hashlib.sha256(token.encode()).hexdigest(),))
def save_run(state):
    if state.get('owner') and state.get('runId') and state['status'] not in ('running','idle'):
        with db() as con: con.execute('INSERT INTO runs VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot',(state['runId'],state['owner'],time.time(),json.dumps(state)))
def history(user_id):
    with db() as con: return [json.loads(row['snapshot']) for row in con.execute('SELECT snapshot FROM runs WHERE user_id=? ORDER BY created DESC LIMIT 20',(user_id,))]
def rename(user_id,name):
    if not isinstance(name,str) or not 1<=len(name.strip())<=80: raise ValueError('Workspace name must be 1–80 characters')
    with db() as con: con.execute('UPDATE users SET workspace=? WHERE id=?',(name.strip(),user_id))
