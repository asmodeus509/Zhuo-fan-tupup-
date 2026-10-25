"""ZHUO FAN HT: backend starter (stdlib only). Set ZHUO_ADMIN_TOKEN and run behind HTTPS reverse proxy."""
import os,sqlite3,json,secrets,hashlib,hmac,datetime
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from http.cookies import SimpleCookie
DB=os.getenv('ZHUO_DB','zhuo.sqlite3'); ADMIN=os.getenv('ZHUO_ADMIN_TOKEN','')
def db():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c
def init():
 with db() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0));
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),expires TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),claimed INTEGER NOT NULL CHECK(claimed>0),reference TEXT NOT NULL UNIQUE,status TEXT NOT NULL DEFAULT 'pending',actual INTEGER,created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),game_id TEXT NOT NULL,game_name TEXT NOT NULL,game_uid TEXT NOT NULL,whatsapp TEXT NOT NULL,diamonds INTEGER NOT NULL,price INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),delta INTEGER NOT NULL,reason TEXT NOT NULL,ref_type TEXT NOT NULL,ref_id INTEGER NOT NULL,created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,UNIQUE(ref_type,ref_id,reason));
CREATE TABLE IF NOT EXISTS packs(id TEXT PRIMARY KEY,diamonds INTEGER NOT NULL,price INTEGER NOT NULL CHECK(price>0),enabled INTEGER NOT NULL DEFAULT 1);''')
  c.executescript("""CREATE TABLE IF NOT EXISTS admins(user_id INTEGER PRIMARY KEY REFERENCES users(id),granted_by INTEGER REFERENCES users(id),created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_audit(id INTEGER PRIMARY KEY,actor_id INTEGER,action TEXT NOT NULL,detail TEXT NOT NULL,created TEXT DEFAULT CURRENT_TIMESTAMP);""")
  for key,value in (('moncash_number',''),('natcash_number',''),('spin_price','50'),('spin_odds_policy','standard'),('guide_channel',''),('guide_video','')):c.execute('INSERT OR IGNORE INTO settings VALUES (?,?)',(key,value))
  try:c.execute("ALTER TABLE payments ADD COLUMN method TEXT NOT NULL DEFAULT 'moncash'")
  except sqlite3.OperationalError:pass
  for n in (110,220,341,572,660,1060,2000):c.execute('INSERT OR IGNORE INTO packs(id,diamonds,price,enabled) VALUES(?,?,?,0)',(str(n),n,1))
def pw(password,salt):return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),310000).hex()
def token_hash(t):return hashlib.sha256(t.encode()).hexdigest()
class API(BaseHTTPRequestHandler):
 def send(self,status,data):
  b=json.dumps(data,ensure_ascii=False).encode();self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def body(self):
  try:
   if int(self.headers.get('Content-Length','0'))>8192:raise ValueError()
   return json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
  except Exception:raise ValueError('JSON invalide')
 def user(self,c):
  h=self.headers.get('Authorization','');t=h[7:] if h.startswith('Bearer ') else ''
  if not t:return None
  return c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>datetime('now')",(token_hash(t),)).fetchone()
 def admin(self,c):
  u=self.user(c)
  if u and c.execute('SELECT 1 FROM admins WHERE user_id=?',(u['id'],)).fetchone():return u['id']
  if ADMIN and hmac.compare_digest(self.headers.get('X-Admin-Token',''),ADMIN):return 0
  return None
 def audit(self,c,actor,action,detail):c.execute('INSERT INTO admin_audit(actor_id,action,detail) VALUES(?,?,?)',(actor or None,action,json.dumps(detail)))

 def do_POST(self):
  try:
   d=self.body();path=self.path.split('?')[0]
   with db() as c:
    if path=='/api/register':
     name=str(d.get('username','')).strip();password=str(d.get('password',''))
     if not 3<=len(name)<=40 or len(password)<12:return self.send(400,{'error':'Pseudo 3–40 caractères, mot de passe 12+ caractères'})
     salt=secrets.token_hex(16);c.execute('INSERT INTO users(username,salt,password_hash) VALUES(?,?,?)',(name,salt,pw(password,salt)));return self.send(201,{'ok':True})
    if path=='/api/login':
     u=c.execute('SELECT * FROM users WHERE username=?',(d.get('username'),)).fetchone()
     if not u or not hmac.compare_digest(pw(str(d.get('password','')),u['salt']),u['password_hash']):return self.send(401,{'error':'Identifiants invalides'})
     t=secrets.token_urlsafe(40);c.execute("INSERT INTO sessions VALUES(?,?,datetime('now','+7 days'))",(token_hash(t),u['id']));return self.send(200,{'token':t,'user':u['username']})
    u=self.user(c)
    if path=='/api/admin/bootstrap':
     if not u or not ADMIN or not hmac.compare_digest(self.headers.get('X-Admin-Token',''),ADMIN):return self.send(403,{'error':'Compte et secret bootstrap requis'})
     if c.execute('SELECT 1 FROM admins LIMIT 1').fetchone():return self.send(409,{'error':'Un premier admin existe déjà'})
     c.execute('INSERT INTO admins(user_id) VALUES (?)',(u['id'],));self.audit(c,u['id'],'bootstrap',{});return self.send(201,{'ok':True})
    if path=='/api/admin/guide':
     actor=self.admin(c)
     if actor is None:return self.send(403,{'error':'Admin non autorisé'})
     channel=str(d.get('channel','')).strip()
     if channel and (not channel.startswith('https://') or len(channel)>500):return self.send(400,{'error':'Lien HTTPS requis'})
     c.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',('guide_channel',channel))
     self.audit(c,actor,'guide_channel',{})
     return self.send(200,{'ok':True})
    if path.startswith('/api/admin/'):
     actor=self.admin(c)
     if actor is None:return self.send(403,{'error':'Admin non autorisé'})
     if path=='/api/admin/add':
      if not actor:return self.send(403,{'error':'Une session admin est requise'})
      name=str(d.get('username','')).strip();target=c.execute('SELECT id FROM users WHERE username=?',(name,)).fetchone()
      if not target:return self.send(404,{'error':'Ce compte doit être créé avant la promotion'})
      c.execute('INSERT OR IGNORE INTO admins(user_id,granted_by) VALUES(?,?)',(target['id'],actor))
      self.audit(c,actor,'add_admin',{'username':name});return self.send(200,{'ok':True})
     if path=='/api/admin/payment-numbers':
      for key in ('moncash_number','natcash_number'):
       val=str(d.get(key,'')).strip()
       if len(val)>35:return self.send(400,{'error':'Numéro trop long'})
       c.execute('UPDATE settings SET value=? WHERE key=?',(val,key))
      self.audit(c,actor,'payment_numbers',{});return self.send(200,{'ok':True})
     if path=='/api/admin/spin-settings':
      price=int(d.get('price',-1));policy=str(d.get('policy','standard'))
      if not 0<=price<=100000 or policy not in ('standard','easy','hard'):return self.send(400,{'error':'Paramètres invalides'})
      for key,value in (('spin_price',str(price)),('spin_odds_policy',policy)):c.execute('UPDATE settings SET value=? WHERE key=?',(value,key))
      self.audit(c,actor,'spin_settings',{'price':price,'policy':policy})
      return self.send(200,{'ok':True,'note':'Les chances réelles nécessitent un tirage serveur documenté ; la politique seule ne modifie pas les résultats.'})
     if path=='/api/admin/pack':
      pid=str(d['id']);price=int(d['price']);enabled=int(bool(d.get('enabled',True)))
      if price<=0 or price>10000000:return self.send(400,{'error':'Prix invalide'})
      c.execute('UPDATE packs SET price=?,enabled=? WHERE id=?',(price,enabled,pid));return self.send(200,{'ok':True})
     if path=='/api/admin/payment':
      pid=int(d['id']);actual=int(d.get('actual',0));approve=bool(d.get('approve',False))
      if actual<0 or actual>10000000:return self.send(400,{'error':'Montant invalide'})
      p=c.execute('SELECT * FROM payments WHERE id=? AND status="pending"',(pid,)).fetchone()
      if not p:return self.send(409,{'error':'Demande déjà traitée'})
      if approve and actual>p['claimed']:return self.send(400,{'error':'Montant reçu supérieur au montant déclaré : revue manuelle requise'})
      c.execute('UPDATE payments SET status=?,actual=? WHERE id=?',('approved' if approve else 'rejected',actual if approve else 0,pid))
      if approve:
       c.execute('UPDATE users SET balance=balance+? WHERE id=?',(actual,p['user_id']))
       c.execute('INSERT INTO ledger(user_id,delta,reason,ref_type,ref_id) VALUES(?,?,?,?,?)',(p['user_id'],actual,'payment_approved','payment',pid))
      return self.send(200,{'ok':True})
     if path=='/api/admin/order':
      oid=int(d['id']);status=str(d['status'])
      if status not in ('delivered','rejected'):return self.send(400,{'error':'Statut invalide'})
      o=c.execute('SELECT * FROM orders WHERE id=? AND status="pending"',(oid,)).fetchone()
      if not o:return self.send(409,{'error':'Commande déjà traitée'})
      c.execute('UPDATE orders SET status=? WHERE id=?',(status,oid))
      if status=='rejected':
       c.execute('UPDATE users SET balance=balance+? WHERE id=?',(o['price'],o['user_id']))
       c.execute('INSERT INTO ledger(user_id,delta,reason,ref_type,ref_id) VALUES(?,?,?,?,?)',(o['user_id'],o['price'],'order_refund','order',oid))
      return self.send(200,{'ok':True})
    if not u:return self.send(401,{'error':'Connexion requise'})
    if path=='/api/payment':
     amount=int(d['claimed']);ref=str(d['reference']).strip();method=str(d.get('method','moncash')).lower()
     if method not in ('moncash','natcash') or not 1<=amount<=10000000 or not 5<=len(ref)<=100:return self.send(400,{'error':'Montant ou référence invalide'})
     c.execute('INSERT INTO payments(user_id,claimed,reference,method) VALUES(?,?,?,?)',(u['id'],amount,ref,method));return self.send(201,{'status':'pending','note':'Aucun crédit avant vérification admin'})
    if path=='/api/order':
     pack=c.execute('SELECT * FROM packs WHERE id=? AND enabled=1',(str(d.get('pack_id')),)).fetchone()
     if not pack:return self.send(400,{'error':'Pack indisponible ou prix non configuré'})
     name=str(d.get('game_name','')).strip();uid=str(d.get('game_uid','')).strip();wa=str(d.get('whatsapp','')).strip()
     if len(name)<2 or not uid.isdigit() or not 5<=len(uid)<=20 or not 8<=len(''.join(x for x in wa if x.isdigit()))<=15:return self.send(400,{'error':'Informations invalides'})
     result=c.execute('UPDATE users SET balance=balance-? WHERE id=? AND balance>=?',(pack['price'],u['id'],pack['price']))
     if result.rowcount!=1:return self.send(409,{'error':'Solde insuffisant'})
     oid=c.execute('INSERT INTO orders(user_id,game_id,game_name,game_uid,whatsapp,diamonds,price) VALUES(?,?,?,?,?,?,?)',(u['id'],pack['id'],name,uid,wa,pack['diamonds'],pack['price'])).lastrowid
     c.execute('INSERT INTO ledger(user_id,delta,reason,ref_type,ref_id) VALUES(?,?,?,?,?)',(u['id'],-pack['price'],'order_debit','order',oid));return self.send(201,{'id':oid,'status':'pending','price':pack['price']})
    return self.send(404,{'error':'Route inconnue'})
  except sqlite3.IntegrityError:return self.send(409,{'error':'Compte ou référence déjà utilisé'})
  except (ValueError,TypeError,KeyError):return self.send(400,{'error':'Paramètres invalides'})
 def do_PUT(self):
  if self.path!='/api/admin/guide-video':return self.send(404,{'error':'Route inconnue'})
  with db() as c:
   actor=self.admin(c)
   if actor is None:return self.send(403,{'error':'Admin non autorisé'})
   mime=self.headers.get('Content-Type','').split(';')[0].lower()
   if mime not in ('video/mp4','video/webm'):return self.send(415,{'error':'MP4 ou WebM uniquement'})
   try:size=int(self.headers.get('Content-Length','0'))
   except ValueError:return self.send(400,{'error':'Taille invalide'})
   if not 0<size<=50*1024*1024:return self.send(413,{'error':'Maximum 50 Mo'})
   content=self.rfile.read(size)
   if not (content.startswith(b'\x1a\x45\xdf\xa3') if mime=='video/webm' else b'ftyp' in content[:32]):return self.send(415,{'error':'Fichier vidéo invalide'})
   folder=os.getenv('ZHUO_MEDIA_DIR','zhuo_media');os.makedirs(folder,exist_ok=True)
   name='guide.'+('mp4' if mime=='video/mp4' else 'webm')
   target=os.path.join(folder,name);tmp=target+'.tmp'
   with open(tmp,'wb') as f:f.write(content)
   os.replace(tmp,target)
   c.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',('guide_video','/api/guide-video'))
   self.audit(c,actor,'guide_video_upload',{'size':size})
   return self.send(200,{'ok':True,'video':'/api/guide-video'})
 def do_GET(self):
  if self.path=='/api/guide-video':
   folder=os.getenv('ZHUO_MEDIA_DIR','zhuo_media')
   files=[('guide.mp4','video/mp4'),('guide.webm','video/webm')]
   for name,mime in files:
    path=os.path.join(folder,name)
    if os.path.isfile(path):
     size=os.path.getsize(path);self.send_response(200);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(size));self.send_header('Cache-Control','public,max-age=60');self.end_headers()
     with open(path,'rb') as f:
      while True:
       block=f.read(65536)
       if not block:break
       self.wfile.write(block)
     return
   return self.send(404,{'error':'Vidéo absente'})
  with db() as c:
   if self.path=='/api/guide':return self.send(200,{'channel':c.execute("SELECT value FROM settings WHERE key='guide_channel'").fetchone()['value'],'video':c.execute("SELECT value FROM settings WHERE key='guide_video'").fetchone()['value']})
   if self.path=='/api/payment-methods':return self.send(200,{'methods':{r['key']:r['value'] for r in c.execute("SELECT key,value FROM settings WHERE key IN ('moncash_number','natcash_number')")}})
   if self.path=='/api/packs':return self.send(200,{'packs':[dict(r) for r in c.execute('SELECT * FROM packs WHERE enabled=1')]})
   if self.path=='/api/admin/settings':
    if self.admin(c) is None:return self.send(403,{'error':'Admin non autorisé'})
    return self.send(200,{'settings':{r['key']:r['value'] for r in c.execute('SELECT * FROM settings')},'admins':[dict(r) for r in c.execute('SELECT users.username,admins.created FROM admins JOIN users ON users.id=admins.user_id')]})
   if self.path=='/api/admin/dashboard':
    if self.admin(c) is None:return self.send(403,{'error':'Admin non autorisé'})
    return self.send(200,{'payments':[dict(r) for r in c.execute('SELECT p.*,u.username FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100')],'orders':[dict(r) for r in c.execute('SELECT o.*,u.username FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 100')]})
   u=self.user(c)
   if not u:return self.send(401,{'error':'Connexion requise'})
   return self.send(200,{'username':u['username'],'balance':u['balance'],'payments':[dict(r) for r in c.execute('SELECT * FROM payments WHERE user_id=? ORDER BY id DESC',(u['id'],))],'orders':[dict(r) for r in c.execute('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC',(u['id'],))],'ledger':[dict(r) for r in c.execute('SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC',(u['id'],))]}) if self.path=='/api/me' else self.send(404,{'error':'Route inconnue'})
if __name__=='__main__':
 init();print('ZHUO API localhost:8765 (deploy behind HTTPS; do not expose directly)');ThreadingHTTPServer(('127.0.0.1',8765),API).serve_forever()
