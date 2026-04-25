// ============================================================
// ORDRE JEDI — MDT BACKEND
// Node.js + Express + SQLite + JWT
// ============================================================
const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'jedi_secret_force_2024_changeme';

app.use(cors());
app.use(express.json({ limit: '10mb' })); // 10mb pour les photos base64
app.use(express.static(path.join(__dirname, '../frontend')));

// ============================================================
// DATABASE INIT
// ============================================================
const db = new Database(path.join(__dirname, 'jedi.db'));

db.exec(`
  PRAGMA journal_mode=WAL;

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'membre',
    membre_id TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS membres (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    rank TEXT NOT NULL,
    spec TEXT DEFAULT '',
    mestre TEXT DEFAULT '',
    bio TEXT DEFAULT '',
    photo TEXT DEFAULT '',
    status TEXT DEFAULT 'actif',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS holocom (
    id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    sender_rank TEXT,
    type TEXT DEFAULT 'info',
    text TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    type TEXT,
    priority TEXT DEFAULT 'normale',
    assignee TEXT DEFAULT '',
    status TEXT DEFAULT 'planifiée',
    description TEXT DEFAULT '',
    deadline TEXT DEFAULT '',
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS rapports (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    type TEXT,
    auteur TEXT NOT NULL,
    contenu TEXT DEFAULT '',
    personnes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS formations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    type TEXT,
    instructeur TEXT,
    participants TEXT DEFAULT '',
    description TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS pouvoirs (
    id TEXT PRIMARY KEY,
    membre TEXT NOT NULL,
    pouvoir TEXT NOT NULL,
    niveau TEXT DEFAULT 'Initié',
    validateur TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS traques (
    id TEXT PRIMARY KEY,
    cible TEXT NOT NULL,
    danger TEXT DEFAULT 'Modéré',
    responsable TEXT,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS prison (
    id TEXT PRIMARY KEY,
    nom TEXT NOT NULL,
    arresteur TEXT,
    motif TEXT DEFAULT '',
    statut TEXT DEFAULT 'détenu',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS casiers (
    id TEXT PRIMARY KEY,
    nom TEXT NOT NULL,
    gravite TEXT DEFAULT 'Mineure',
    infraction TEXT DEFAULT '',
    sanction TEXT DEFAULT '',
    agent TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS promotions (
    id TEXT PRIMARY KEY,
    membre TEXT NOT NULL,
    membre_id TEXT,
    rank_old TEXT,
    rank_new TEXT,
    promoteur TEXT,
    note TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Créer le compte admin par défaut si inexistant
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const bcryptjs = require('bcryptjs');
  const hash = bcryptjs.hashSync('admin1234', 10);
  const uid = 'u_' + Date.now();
  db.prepare('INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)').run(uid, 'admin', hash, 'admin');
  console.log('✅ Compte admin créé — login: admin / mdp: admin1234');
}

// ============================================================
// MIDDLEWARE AUTH
// ============================================================
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Non authentifié' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin' && req.user.role !== 'maitre') {
    return res.status(403).json({ error: 'Accès refusé — rang insuffisant' });
  }
  next();
}

const UID = () => 'id_' + Date.now().toString(36) + Math.random().toString(36).slice(2);

// ============================================================
// AUTH ROUTES
// ============================================================

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Identifiants requis' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user) return res.status(401).json({ error: 'Compte introuvable' });

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Mot de passe incorrect' });

  // Récupérer le membre lié si existe
  let membre = null;
  if (user.membre_id) {
    membre = db.prepare('SELECT * FROM membres WHERE id = ?').get(user.membre_id);
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, membre_id: user.membre_id },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({ token, user: { id: user.id, username: user.username, role: user.role, membre } });
});

// POST /api/auth/register (admin only)
app.post('/api/auth/register', authMiddleware, adminOnly, (req, res) => {
  const { username, password, role, membre_id } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs requis' });

  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (exists) return res.status(409).json({ error: 'Nom d\'utilisateur déjà pris' });

  const hash = bcrypt.hashSync(password, 10);
  const id = UID();
  db.prepare('INSERT INTO users (id, username, password_hash, role, membre_id) VALUES (?, ?, ?, ?, ?)')
    .run(id, username.trim(), hash, role || 'membre', membre_id || null);

  res.json({ success: true, id });
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, username, role, membre_id FROM users WHERE id = ?').get(req.user.id);
  let membre = null;
  if (user.membre_id) membre = db.prepare('SELECT * FROM membres WHERE id = ?').get(user.membre_id);
  res.json({ ...user, membre });
});

// GET /api/auth/users (admin)
app.get('/api/auth/users', authMiddleware, adminOnly, (req, res) => {
  const users = db.prepare('SELECT id, username, role, membre_id, created_at FROM users').all();
  res.json(users);
});

// DELETE /api/auth/users/:id (admin)
app.delete('/api/auth/users/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// PUT /api/auth/password
app.put('/api/auth/password', authMiddleware, (req, res) => {
  const { old_password, new_password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(old_password, user.password_hash)) return res.status(401).json({ error: 'Ancien mot de passe incorrect' });
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  res.json({ success: true });
});

// ============================================================
// MEMBRES
// ============================================================
app.get('/api/membres', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM membres ORDER BY created_at DESC').all());
});

app.post('/api/membres', authMiddleware, (req, res) => {
  const { name, rank, spec, mestre, bio, photo, status } = req.body;
  if (!name || !rank) return res.status(400).json({ error: 'Champs requis' });
  const id = UID();
  db.prepare('INSERT INTO membres (id, name, rank, spec, mestre, bio, photo, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, name, rank, spec||'', mestre||'', bio||'', photo||'', status||'actif');
  res.json({ success: true, id });
});

app.put('/api/membres/:id', authMiddleware, (req, res) => {
  const { name, rank, spec, mestre, bio, photo, status } = req.body;
  db.prepare('UPDATE membres SET name=?, rank=?, spec=?, mestre=?, bio=?, photo=?, status=? WHERE id=?')
    .run(name, rank, spec||'', mestre||'', bio||'', photo||'', status||'actif', req.params.id);
  res.json({ success: true });
});

app.delete('/api/membres/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM membres WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// HOLOCOM
// ============================================================
app.get('/api/holocom', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM holocom ORDER BY created_at DESC LIMIT 100').all());
});

app.post('/api/holocom', authMiddleware, (req, res) => {
  const { text, type } = req.body;
  if (!text) return res.status(400).json({ error: 'Message requis' });
  const user = db.prepare('SELECT *, (SELECT rank FROM membres WHERE id = users.membre_id) as rank FROM users WHERE id = ?').get(req.user.id);
  const id = UID();
  db.prepare('INSERT INTO holocom (id, sender, sender_rank, type, text) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.user.username, user?.rank || '', type || 'info', text);
  res.json({ success: true, id });
});

app.delete('/api/holocom/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM holocom WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// MISSIONS
// ============================================================
app.get('/api/missions', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM missions ORDER BY created_at DESC').all());
});

app.post('/api/missions', authMiddleware, (req, res) => {
  const { title, type, priority, assignee, status, description, deadline } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis' });
  const id = UID();
  db.prepare('INSERT INTO missions (id, title, type, priority, assignee, status, description, deadline, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, title, type||'Patrouille', priority||'normale', assignee||'', status||'planifiée', description||'', deadline||'', req.user.username);
  res.json({ success: true, id });
});

app.put('/api/missions/:id', authMiddleware, (req, res) => {
  const { title, type, priority, assignee, status, description, deadline } = req.body;
  db.prepare('UPDATE missions SET title=?, type=?, priority=?, assignee=?, status=?, description=?, deadline=? WHERE id=?')
    .run(title, type, priority, assignee||'', status, description||'', deadline||'', req.params.id);
  res.json({ success: true });
});

app.delete('/api/missions/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM missions WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// RAPPORTS
// ============================================================
app.get('/api/rapports', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM rapports ORDER BY created_at DESC').all());
});

app.post('/api/rapports', authMiddleware, (req, res) => {
  const { title, type, contenu, personnes } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis' });
  const id = UID();
  db.prepare('INSERT INTO rapports (id, title, type, auteur, contenu, personnes) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, title, type||'Mission', req.user.username, contenu||'', personnes||'');
  res.json({ success: true, id });
});

app.delete('/api/rapports/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM rapports WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// FORMATIONS
// ============================================================
app.get('/api/formations', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM formations ORDER BY created_at DESC').all());
});

app.post('/api/formations', authMiddleware, (req, res) => {
  const { title, type, instructeur, participants, description } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis' });
  const id = UID();
  db.prepare('INSERT INTO formations (id, title, type, instructeur, participants, description) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, title, type||'Combat au sabre', instructeur||'', participants||'', description||'');
  res.json({ success: true, id });
});

app.delete('/api/formations/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM formations WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// POUVOIRS
// ============================================================
app.get('/api/pouvoirs', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM pouvoirs ORDER BY created_at DESC').all());
});

app.post('/api/pouvoirs', authMiddleware, (req, res) => {
  const { membre, pouvoir, niveau, validateur } = req.body;
  if (!membre || !pouvoir) return res.status(400).json({ error: 'Champs requis' });
  const id = UID();
  db.prepare('INSERT INTO pouvoirs (id, membre, pouvoir, niveau, validateur) VALUES (?, ?, ?, ?, ?)')
    .run(id, membre, pouvoir, niveau||'Initié', validateur||'');
  res.json({ success: true, id });
});

app.delete('/api/pouvoirs/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM pouvoirs WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// TRAQUES
// ============================================================
app.get('/api/traques', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM traques ORDER BY created_at DESC').all());
});

app.post('/api/traques', authMiddleware, (req, res) => {
  const { cible, danger, responsable, description } = req.body;
  if (!cible) return res.status(400).json({ error: 'Cible requise' });
  const id = UID();
  db.prepare('INSERT INTO traques (id, cible, danger, responsable, description, status) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, cible, danger||'Modéré', responsable||'', description||'', 'active');
  res.json({ success: true, id });
});

app.put('/api/traques/:id', authMiddleware, (req, res) => {
  const { status } = req.body;
  db.prepare('UPDATE traques SET status=? WHERE id=?').run(status, req.params.id);
  res.json({ success: true });
});

app.delete('/api/traques/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM traques WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// PRISON
// ============================================================
app.get('/api/prison', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM prison ORDER BY created_at DESC').all());
});

app.post('/api/prison', authMiddleware, (req, res) => {
  const { nom, arresteur, motif } = req.body;
  if (!nom) return res.status(400).json({ error: 'Nom requis' });
  const id = UID();
  db.prepare('INSERT INTO prison (id, nom, arresteur, motif, statut) VALUES (?, ?, ?, ?, ?)')
    .run(id, nom, arresteur||'', motif||'', 'détenu');
  res.json({ success: true, id });
});

app.put('/api/prison/:id', authMiddleware, (req, res) => {
  db.prepare('UPDATE prison SET statut=? WHERE id=?').run(req.body.statut, req.params.id);
  res.json({ success: true });
});

app.delete('/api/prison/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM prison WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// CASIERS
// ============================================================
app.get('/api/casiers', authMiddleware, (req, res) => {
  const { nom } = req.query;
  if (nom) {
    res.json(db.prepare("SELECT * FROM casiers WHERE nom LIKE ? ORDER BY created_at DESC").all(`%${nom}%`));
  } else {
    res.json(db.prepare('SELECT * FROM casiers ORDER BY created_at DESC').all());
  }
});

app.post('/api/casiers', authMiddleware, (req, res) => {
  const { nom, gravite, infraction, sanction } = req.body;
  if (!nom) return res.status(400).json({ error: 'Nom requis' });
  const id = UID();
  db.prepare('INSERT INTO casiers (id, nom, gravite, infraction, sanction, agent) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, nom, gravite||'Mineure', infraction||'', sanction||'', req.user.username);
  res.json({ success: true, id });
});

app.delete('/api/casiers/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM casiers WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// PROMOTIONS
// ============================================================
app.get('/api/promotions', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM promotions ORDER BY created_at DESC').all());
});

app.post('/api/promotions', authMiddleware, adminOnly, (req, res) => {
  const { membre, membre_id, rank_old, rank_new, note } = req.body;
  if (!membre || !rank_new) return res.status(400).json({ error: 'Champs requis' });
  const id = UID();
  db.prepare('INSERT INTO promotions (id, membre, membre_id, rank_old, rank_new, promoteur, note) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, membre, membre_id||'', rank_old||'', rank_new, req.user.username, note||'');
  // Mettre à jour le rang du membre
  if (membre_id) {
    db.prepare('UPDATE membres SET rank=? WHERE id=?').run(rank_new, membre_id);
  }
  res.json({ success: true, id });
});

// ============================================================
// STATS
// ============================================================
app.get('/api/stats', authMiddleware, (req, res) => {
  res.json({
    membres: db.prepare('SELECT COUNT(*) as c FROM membres').get().c,
    membres_actifs: db.prepare("SELECT COUNT(*) as c FROM membres WHERE status='actif'").get().c,
    missions: db.prepare('SELECT COUNT(*) as c FROM missions').get().c,
    missions_actives: db.prepare("SELECT COUNT(*) as c FROM missions WHERE status='en-cours'").get().c,
    rapports: db.prepare('SELECT COUNT(*) as c FROM rapports').get().c,
    traques: db.prepare("SELECT COUNT(*) as c FROM traques WHERE status='active'").get().c,
  });
});

// ============================================================
// START
// ============================================================
app.listen(PORT, () => {
  console.log(`🚀 Serveur MDT Jedi démarré sur http://localhost:${PORT}`);
  console.log(`📦 Base de données: jedi.db`);
});
