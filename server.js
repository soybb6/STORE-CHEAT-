
import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import csrf from 'csurf';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import morgan from 'morgan';
import Database from 'better-sqlite3';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as DiscordStrategy } from 'passport-discord';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const SQLiteStore = SQLiteStoreFactory(session);
const db = new Database(path.join(__dirname, 'db.sqlite'));

app.set('view engine','ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname,'public')));
app.use(helmet());
app.use(morgan('dev'));
app.use(rateLimit({windowMs: 15*60*1000, limit: 300}));

// Sessions
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 1000*60*60*24*7 }
}));

// CSRF
const csrfProtection = csrf();

// DB setup
db.exec(`
  CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT, provider_id TEXT, name TEXT,
    is_admin INTEGER DEFAULT 0,
    licensed INTEGER DEFAULT 0
  );
  CREATE UNIQUE INDEX IF NOT EXISTS users_provider_idx ON users(provider, provider_id);
  CREATE TABLE IF NOT EXISTS products(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT, title TEXT, description TEXT,
    image_url TEXT, download_url TEXT
  );
  CREATE TABLE IF NOT EXISTS keys(
    code TEXT PRIMARY KEY,
    used_by INTEGER REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS tickets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, subject TEXT, message TEXT,
    status TEXT DEFAULT 'open', reply TEXT
  );
`);

// Seed: categories demo products (only if empty)
const prodCount = db.prepare('SELECT COUNT(*) c FROM products').get().c;
if (!prodCount) {
  const ins = db.prepare('INSERT INTO products(category,title,description,image_url,download_url) VALUES (?,?,?,?,?)');
  ins.run('roblox','Roblox Tool','Herramienta demo', '', 'https://example.com/roblox.zip');
  ins.run('mta','MTA Pack','Paquete demo', '', 'https://example.com/mta.zip');
  ins.run('spoofers','Spoofer Lite','Demo', '', 'https://example.com/spoofer.zip');
}

// Seed: 30 keys if empty
const keyCount = db.prepare('SELECT COUNT(*) c FROM keys').get().c;
function randomKey(){
  const letters='abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ';
  let s=''; for(let i=0;i<12;i++) s+=letters[Math.floor(Math.random()*letters.length)];
  return s;
}
if (!keyCount) {
  const insk = db.prepare('INSERT INTO keys(code) VALUES (?)');
  for(let i=0;i<30;i++) insk.run(randomKey());
}

// Passport
passport.serializeUser((user, done)=>done(null, user.id));
passport.deserializeUser((id, done)=>{
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  done(null, u || null);
});

const haveGoogle = process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET;
const haveDiscord = process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

if (haveGoogle) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/auth/google/callback`
  }, (accessToken, refreshToken, profile, done)=>{
    try{
      const id = profile.id;
      const name = profile.displayName || 'GoogleUser';
      const row = db.prepare('SELECT * FROM users WHERE provider=? AND provider_id=?').get('google', id);
      let user = row;
      if(!row){
        const anyAdmin = db.prepare('SELECT COUNT(*) c FROM users WHERE is_admin=1').get().c;
        const info = db.prepare('INSERT INTO users(provider,provider_id,name,is_admin) VALUES (?,?,?,?)')
          .run('google', id, name, anyAdmin?0:1);
        user = db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
      }
      return done(null, user);
    }catch(e){ return done(e); }
  }));
}
if (haveDiscord) {
  passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/auth/discord/callback`,
    scope: ['identify','email']
  }, (accessToken, refreshToken, profile, done)=>{
    try{
      const id = profile.id;
      const name = profile.username || 'DiscordUser';
      const row = db.prepare('SELECT * FROM users WHERE provider=? AND provider_id=?').get('discord', id);
      let user = row;
      if(!row){
        const anyAdmin = db.prepare('SELECT COUNT(*) c FROM users WHERE is_admin=1').get().c;
        const info = db.prepare('INSERT INTO users(provider,provider_id,name,is_admin) VALUES (?,?,?,?)')
          .run('discord', id, name, anyAdmin?0:1);
        user = db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
      }
      return done(null, user);
    }catch(e){ return done(e); }
  }));
}

app.use(passport.initialize());
app.use(passport.session());

// Helpers
function requireAuth(req,res,next){ if(req.user) return next(); res.redirect('/login'); }
function requireAdmin(req,res,next){ if(req.user?.is_admin) return next(); res.status(403).send('Solo admin'); }

// Views helper
app.use((req,res,next)=>{
  res.locals.user = req.user;
  res.locals.providers = { google: !!haveGoogle, discord: !!haveDiscord };
  next();
});

// Routes
app.get('/login',(req,res)=> res.render('login',{title:'Login'}));
if (haveGoogle) {
  app.get('/auth/google', passport.authenticate('google', { scope: ['profile','email'] }));
  app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect:'/login' }),(req,res)=>res.redirect('/'));
}
if (haveDiscord) {
  app.get('/auth/discord', passport.authenticate('discord'));
  app.get('/auth/discord/callback', passport.authenticate('discord',{failureRedirect:'/login'}),(req,res)=>res.redirect('/'));
}
// Dev login if no OAuth configured
if (!haveGoogle && !haveDiscord) {
  app.get('/auth/dev',(req,res)=>{
    const name='DevUser '+Math.floor(Math.random()*1000);
    const anyAdmin = db.prepare('SELECT COUNT(*) c FROM users WHERE is_admin=1').get().c;
    const info = db.prepare('INSERT INTO users(provider,provider_id,name,is_admin) VALUES (?,?,?,?)').run('dev', String(Date.now()), name, anyAdmin?0:1);
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
    req.login(user, ()=> res.redirect('/'));
  });
}

app.get('/logout',(req,res)=>{ req.logout(()=>{}); res.redirect('/'); });

// Home + categories
app.get('/', csrfProtection, (req,res)=>{
  const products = db.prepare('SELECT * FROM products ORDER BY id DESC').all();
  res.render('index',{title:'BB6', products, csrfToken: req.csrfToken()});
});
app.get('/category/:slug', csrfProtection, (req,res)=>{
  const cat = req.params.slug;
  const products = db.prepare('SELECT * FROM products WHERE category=? ORDER BY id DESC').all(cat);
  res.render('category',{title:cat, category:cat, products, csrfToken: req.csrfToken()});
});

// Download (with key once)
app.post('/download/:id', requireAuth, csrfProtection, (req,res)=>{
  const user = req.user;
  const prod = db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id);
  if(!prod) return res.status(404).send('Producto no existe');
  if (!user.licensed) {
    const key = (req.body.key||'').trim();
    if (!key) return res.status(400).send('Falta clave');
    const row = db.prepare('SELECT * FROM keys WHERE code=?').get(key);
    if (!row) return res.status(400).send('Clave inválida');
    if (row.used_by) return res.status(400).send('Clave ya usada');
    const tx = db.transaction(()=>{
      db.prepare('UPDATE keys SET used_by=? WHERE code=?').run(user.id, key);
      db.prepare('UPDATE users SET licensed=1 WHERE id=?').run(user.id);
    });
    tx();
  }
  // allow
  res.redirect(prod.download_url);
});

// Support
app.get('/support', requireAuth, csrfProtection, (req,res)=>{
  const tickets = db.prepare('SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC').all(req.user.id);
  res.render('support/index',{title:'Soport', tickets, csrfToken: req.csrfToken()});
});
app.post('/support', requireAuth, csrfProtection, (req,res)=>{
  const {subject, message} = req.body;
  db.prepare('INSERT INTO tickets(user_id,subject,message) VALUES (?,?,?)').run(req.user.id, subject, message);
  res.redirect('/support');
});

// Admin
app.get('/admin', requireAuth, requireAdmin, csrfProtection, (req,res)=>{
  const users = db.prepare('SELECT * FROM users ORDER BY id DESC').all();
  const keys = db.prepare('SELECT code, used_by FROM keys ORDER BY used_by IS NOT NULL, code').all();
  const products = db.prepare('SELECT * FROM products ORDER BY id DESC').all();
  const tickets = db.prepare('SELECT t.*, u.name as user_name FROM tickets t LEFT JOIN users u ON u.id=t.user_id ORDER BY t.id DESC').all();
  res.render('admin/index',{title:'Admin', users, keys, products, tickets, csrfToken: req.csrfToken()});
});
app.post('/admin/keys/generate', requireAuth, requireAdmin, csrfProtection, (req,res)=>{
  const ins = db.prepare('INSERT OR IGNORE INTO keys(code) VALUES (?)');
  const letters='abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ';
  function r(){ let s=''; for(let i=0;i<12;i++) s+=letters[Math.floor(Math.random()*letters.length)]; return s; }
  for(let i=0;i<30;i++) ins.run(r());
  res.redirect('/admin');
});
app.post('/admin/products/new', requireAuth, requireAdmin, csrfProtection, (req,res)=>{
  const {category,title,description,image_url,download_url} = req.body;
  db.prepare('INSERT INTO products(category,title,description,image_url,download_url) VALUES (?,?,?,?,?)')
    .run(category,title,description,image_url,download_url);
  res.redirect('/admin');
});
app.post('/admin/tickets/:id/reply', requireAuth, requireAdmin, csrfProtection, (req,res)=>{
  db.prepare('UPDATE tickets SET reply=?, status="answered" WHERE id=?').run(req.body.reply, req.params.id);
  res.redirect('/admin');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log('BB6 listening on '+PORT));
