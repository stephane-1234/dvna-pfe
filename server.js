'use strict';

const express    = require('express');
const session    = require('express-session');
const bodyParser = require('body-parser');
const path       = require('path');
const { spawn }  = require('child_process');
const helmet     = require('helmet');
const crypto     = require('crypto');

const app = express();

// FIX-1 (Gitleaks): Secrets via variables d'environnement
const JWT_SECRET    = process.env.JWT_SECRET;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
if (!JWT_SECRET || !ADMIN_API_KEY) {
  console.error('[ERREUR] JWT_SECRET et ADMIN_API_KEY doivent etre definis dans .env');
  process.exit(1);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// FIX-7 (ZAP): Helmet active — tous les headers de securite
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'"],
      styleSrc:       ["'self'", "'unsafe-inline'"],
      imgSrc:         ["'self'", "data:"],
      fontSrc:        ["'self'"],
      objectSrc:      ["'none'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy:   { policy: "same-origin" },
  crossOriginResourcePolicy: { policy: "same-origin" },
  referrerPolicy:            { policy: "strict-origin-when-cross-origin" },
  permittedCrossDomainPolicies: { permittedPolicies: "none" },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  next();
});

// FIX-2 (Semgrep): Cookie de session securise
app.use(session({
  name:   'dvna_sess',
  secret: JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, sameSite: 'strict', maxAge: 3600000, path: '/' }
}));

const users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'alice', password: 'alice123', role: 'user'  },
  { id: 3, username: 'bob',   password: 'bob123',   role: 'user'  }
];

const notes = [
  { id: 1, userId: 1, title: 'Note admin', content: 'Ceci est une note privee admin.' },
  { id: 2, userId: 2, title: 'Note Alice', content: 'Note privee de Alice.' }
];

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function generateCsrfToken() { return crypto.randomBytes(32).toString('hex'); }

function requireCsrf(req, res, next) {
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken)
    return res.status(403).render('error', { user: req.session.user || null, message: 'Token CSRF invalide.' });
  next();
}

app.get('/', (req, res) => res.render('index', { user: req.session.user || null }));

app.get('/login', (req, res) => {
  req.session.csrfToken = generateCsrfToken();
  res.render('login', { error: null, user: null, csrfToken: req.session.csrfToken });
});

app.post('/login', requireCsrf, (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (user) {
    req.session.regenerate((err) => {
      if (err) return res.status(500).render('error', { user: null, message: 'Erreur serveur' });
      req.session.user      = { id: user.id, username: user.username, role: user.role };
      req.session.csrfToken = generateCsrfToken();
      res.redirect('/dashboard');
    });
  } else {
    req.session.csrfToken = generateCsrfToken();
    res.render('login', { error: 'Identifiants incorrects', user: null, csrfToken: req.session.csrfToken });
  }
});

app.get('/logout', (req, res) => { req.session.destroy(() => res.redirect('/')); });
app.get('/dashboard', requireAuth, (req, res) => res.render('dashboard', { user: req.session.user }));

// FIX-3 (SAST): spawn() + validation IPv4 stricte
app.get('/ping', requireAuth, (req, res) =>
  res.render('ping', { user: req.session.user, result: null, error: null }));

app.post('/ping', requireAuth, (req, res) => {
  const host  = (req.body.host || '').trim();
  const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match || match.slice(1).some(o => parseInt(o) > 255))
    return res.render('ping', { user: req.session.user, result: null, error: 'Adresse IPv4 invalide (ex: 192.168.1.1)' });

  const ping = spawn('ping', ['-n', '2', host]);
  let output = '';
  ping.stdout.on('data', d => { output += d.toString(); });
  ping.stderr.on('data', d => { output += d.toString(); });
  ping.on('close', () => res.render('ping', { user: req.session.user, result: output, error: null }));
});

// FIX-4 (XSS): EJS echappe avec <%= %> — pas de <%- %>
app.get('/search', requireAuth, (req, res) => {
  const query  = req.query.q || '';
  const result = users.filter(u => u.username.includes(query));
  res.render('search', { user: req.session.user, query, result });
});

// FIX-5 (IDOR): verification d'appartenance de la note
app.get('/notes', requireAuth, (req, res) =>
  res.render('notes', { user: req.session.user, notes: notes.filter(n => n.userId === req.session.user.id) }));

app.get('/note/:id', requireAuth, (req, res) => {
  const note = notes.find(n => n.id === parseInt(req.params.id));
  if (!note) return res.status(404).render('error', { user: req.session.user, message: 'Note introuvable' });
  if (note.userId !== req.session.user.id && req.session.user.role !== 'admin')
    return res.status(403).render('error', { user: req.session.user, message: 'Acces interdit a cette note' });
  res.render('note', { user: req.session.user, note });
});

// FIX-6 (SCA): JSON.parse() — node-serialize supprime
app.get('/deserialize', requireAuth, (req, res) =>
  res.render('deserialize', { user: req.session.user, result: null }));

app.post('/deserialize', requireAuth, (req, res) => {
  try {
    const data = JSON.parse(req.body.payload);
    res.render('deserialize', { user: req.session.user, result: JSON.stringify(data, null, 2) });
  } catch (e) {
    res.render('deserialize', { user: req.session.user, result: 'JSON invalide : ' + e.message });
  }
});

// FIX-7 (XXE): @xmldom/xmldom + rejet DOCTYPE/ENTITY
app.get('/xml', requireAuth, (req, res) =>
  res.render('xml', { user: req.session.user, result: null }));

app.post('/xml', requireAuth, (req, res) => {
  try {
    const xmlInput = (req.body.xml || '').trim();
    if (/<!DOCTYPE|<!ENTITY|SYSTEM\s+["']/i.test(xmlInput))
      return res.render('xml', { user: req.session.user, result: 'DOCTYPE/ENTITY interdit — risque XXE' });
    const { DOMParser } = require('@xmldom/xmldom');
    const doc   = new DOMParser().parseFromString(xmlInput, 'text/xml');
    const xpath = require('xpath');
    res.render('xml', { user: req.session.user, result: String(xpath.select('string(//value)', doc)) });
  } catch (e) {
    res.render('xml', { user: req.session.user, result: 'Erreur de parsing XML' });
  }
});

app.use((req, res) => res.status(404).render('error', { user: req.session.user || null, message: 'Page introuvable' }));

const PORT = process.env.PORT || 9090;
app.listen(PORT, () => console.log(`DVNA-PFE SECURE sur http://localhost:${PORT}`));
module.exports = app;
