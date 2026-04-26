// ============================================================
// ORDRE JEDI — MDT BACKEND v2
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
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../frontend')));

const db = new Database(path.join(__dirname, 'jedi.db'));
db.exec('PRAGMA journal_mode=WAL;');

// ============================================================
// SCHEMA
// ============================================================
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'pending',
    spec TEXT DEFAULT '',
    membre_id TEXT,
    status TEXT DEFAULT 'pending',
    approved_by TEXT DEFAULT '',
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
    domaine TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS annonces (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    contenu TEXT NOT NULL,
    auteur TEXT NOT NULL,
    auteur_rank TEXT DEFAULT '',
    section TEXT DEFAULT 'general',
    pinned INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS interrogations (
    id TEXT PRIMARY KEY,
    suspect TEXT NOT NULL,
    interrogateur TEXT NOT NULL,
    type TEXT DEFAULT 'standard',
    lieu TEXT DEFAULT '',
    contenu TEXT DEFAULT '',
    resultat TEXT DEFAULT '',
    statut TEXT DEFAULT 'ouvert',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS infirmerie (
    id TEXT PRIMARY KEY,
    patient TEXT NOT NULL,
    medecin TEXT NOT NULL,
    diagnostic TEXT DEFAULT '',
    traitement TEXT DEFAULT '',
    statut TEXT DEFAULT 'en-traitement',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS cours (
    id TEXT PRIMARY KEY,
    titre TEXT NOT NULL,
    instructeur TEXT NOT NULL,
    type TEXT DEFAULT 'général',
    participants TEXT DEFAULT '',
    contenu TEXT DEFAULT '',
    date_cours TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    type TEXT DEFAULT 'Patrouille',
    priority TEXT DEFAULT 'normale',
    assignee TEXT DEFAULT '',
    status TEXT DEFAULT 'planifiée',
    description TEXT DEFAULT '',
    deadline TEXT DEFAULT '',
    spec TEXT DEFAULT 'general',
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS rapports (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    type TEXT DEFAULT 'Mission',
    section TEXT DEFAULT 'general',
    auteur TEXT NOT NULL,
    contenu TEXT DEFAULT '',
    personnes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS formations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    type TEXT DEFAULT 'Combat au sabre',
    instructeur TEXT DEFAULT '',
    participants TEXT DEFAULT '',
    description TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS pouvoirs (
    id TEXT PRIMARY KEY,
    membre TEXT NOT NULL,
    pouvoir TEXT NOT NULL,
    niveau TEXT DEFAULT 'Initié',
    validateur TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS traques (
    id TEXT PRIMARY KEY,
    cible TEXT NOT NULL,
    danger TEXT DEFAULT 'Modéré',
    responsable TEXT DEFAULT '',
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS prison (
    id TEXT PRIMARY KEY,
    nom TEXT NOT NULL,
    arresteur TEXT DEFAULT '',
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
    agent TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS promotions (
    id TEXT PRIMARY KEY,
    membre TEXT NOT NULL,
    membre_id TEXT DEFAULT '',
    rank_old TEXT DEFAULT '',
    rank_new TEXT NOT NULL,
    promoteur TEXT NOT NULL,
    note TEXT DEFAULT '',
    spec TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS holocom (
    id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    sender_rank TEXT DEFAULT '',
    type TEXT DEFAULT 'info',
    text TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS presentations (
    id TEXT PRIMARY KEY,
    spec TEXT NOT NULL,
    titre TEXT NOT NULL,
    contenu TEXT DEFAULT '',
    auteur TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS infos (
    id TEXT PRIMARY KEY,
    section TEXT NOT NULL,
    titre TEXT NOT NULL,
    contenu TEXT DEFAULT '',
    auteur TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Migrations pour base existante
const migrations = [
  `ALTER TABLE users ADD COLUMN spec TEXT DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'`,
  `ALTER TABLE users ADD COLUMN approved_by TEXT DEFAULT ''`,
  `ALTER TABLE membres ADD COLUMN domaine TEXT DEFAULT ''`,
  `ALTER TABLE missions ADD COLUMN spec TEXT DEFAULT 'general'`,
  `ALTER TABLE rapports ADD COLUMN section TEXT DEFAULT 'general'`,
  `ALTER TABLE promotions ADD COLUMN spec TEXT DEFAULT ''`,
];
for (const m of migrations) { try { db.exec(m); } catch(e) {} }

// Activer les anciens comptes admin/maitre existants
db.exec(`UPDATE users SET status='active' WHERE status IS NULL OR status=''`);

// Compte admin par défaut
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin1234', 10);
  const uid = 'u_' + Date.now();
  db.prepare('INSERT INTO users (id, username, password_hash, role, status) VALUES (?, ?, ?, ?, ?)').run(uid, 'admin', hash, 'admin', 'active');
  console.log('✅ Admin créé — login: admin / mdp: admin1234');
}

const UID = () => 'id_' + Date.now().toString(36) + Math.random().toString(36).slice(2);

// ============================================================
// HELPERS DE RÔLES
// ============================================================
const ADMIN_ROLES = ['admin', 'maitre-ordre', 'haut-conseil', 'maitre-jedi'];
const MAITRE_SPEC_ROLES = ['maitre-spec', 'maitre-ombres', 'maitre-sentinelles', 'maitre-gardiens', 'maitre-erudits'];
const MAITRE_ROLES = [...ADMIN_ROLES, ...MAITRE_SPEC_ROLES];
const CAN_APPROVE_ROLES = MAITRE_ROLES;
const DOMAINE_ROLES = ['chevalier', 'consulaire', 'apprenti'];

// Mapping grade → spec
const SPEC_BY_RANK = {
  'maitre-ombres':'Ombre','grande-ombre':'Ombre','ombre':'Ombre',
  'maitre-erudits':'Érudit','grand-erudit':'Érudit','erudit':'Érudit',
  'maitre-gardiens':'Gardien','grand-gardien':'Gardien','gardien':'Gardien',
  'maitre-sentinelles':'Sentinelle','grande-sentinelle':'Sentinelle','sentinelle':'Sentinelle'
};
// Grades du Conseil → réservés à admin/conseil/maitre-jedi
const HIGH_COUNCIL_RANKS = ['maitre-jedi','haut-conseil','maitre-ordre'];

function isAdmin(role) { return ADMIN_ROLES.includes(role); }
function isMaitre(role) { return MAITRE_ROLES.includes(role); }
function canApprove(role) { return CAN_APPROVE_ROLES.includes(role); }

// Récupère la spec effective d'un user (depuis son rôle ou son champ spec)
function getSpecOfUser(user) {
  if (SPEC_BY_RANK[user.role]) return SPEC_BY_RANK[user.role];
  return user.spec || '';
}

// ============================================================
// MIDDLEWARES
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

function activeOnly(req, res, next) {
  const user = db.prepare('SELECT status, role FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(401).json({ error: 'Compte introuvable' });
  if (user.status === 'pending') return res.status(403).json({ error: 'pending', message: 'Compte en attente d\'approbation' });
  if (user.status === 'rejected') return res.status(403).json({ error: 'rejected', message: 'Compte refusé' });
  next();
}

function adminOnly(req, res, next) {
  if (!isAdmin(req.user.role)) return res.status(403).json({ error: 'Accès refusé — rang insuffisant' });
  next();
}

function maitreOnly(req, res, next) {
  if (!isMaitre(req.user.role)) return res.status(403).json({ error: 'Rang insuffisant — Maître requis' });
  next();
}

function approverOnly(req, res, next) {
  if (!canApprove(req.user.role)) return res.status(403).json({ error: 'Rang insuffisant — Maître de Spécialisation minimum requis' });
  next();
}

// ============================================================
// AUTH — INSCRIPTION PUBLIQUE
// ============================================================
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !username.trim() || !password) return res.status(400).json({ error: 'Nom de personnage et mot de passe requis' });
  if (password.length < 4) return res.status(400).json({ error: 'Mot de passe trop court (4 caractères minimum)' });

  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim());
  if (exists) return res.status(409).json({ error: 'Ce nom de personnage est déjà utilisé' });

  const hash = bcrypt.hashSync(password, 10);
  const id = UID();
  db.prepare('INSERT INTO users (id, username, password_hash, role, status) VALUES (?, ?, ?, ?, ?)').run(id, username.trim(), hash, 'pending', 'pending');
  res.json({ success: true, message: 'Compte créé — en attente d\'approbation par un Maître de Spécialisation' });
});

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Identifiants requis' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user) return res.status(401).json({ error: 'Compte introuvable' });
  if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Mot de passe incorrect' });

  let membre = null;
  if (user.membre_id) membre = db.prepare('SELECT * FROM membres WHERE id = ?').get(user.membre_id);

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, spec: user.spec || '', status: user.status, membre_id: user.membre_id },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, spec: user.spec || '', status: user.status, membre } });
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, username, role, spec, status, membre_id, approved_by FROM users WHERE id = ?').get(req.user.id);
  let membre = null;
  if (user?.membre_id) membre = db.prepare('SELECT * FROM membres WHERE id = ?').get(user.membre_id);
  res.json({ ...user, membre });
});

// GET /api/auth/users (maîtres+)
app.get('/api/auth/users', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  const users = db.prepare('SELECT id, username, role, spec, status, membre_id, approved_by, created_at FROM users ORDER BY created_at DESC').all();
  const membres = db.prepare('SELECT id, name FROM membres').all();
  res.json(users.map(u => ({ ...u, membre_name: membres.find(m => m.id === u.membre_id)?.name || null })));
});

// GET /api/auth/pending (approbateurs+)
app.get('/api/auth/pending', authMiddleware, activeOnly, approverOnly, (req, res) => {
  res.json(db.prepare("SELECT id, username, created_at FROM users WHERE status='pending' ORDER BY created_at ASC").all());
});

// PUT /api/auth/approve/:id
app.put('/api/auth/approve/:id', authMiddleware, activeOnly, approverOnly, (req, res) => {
  const { role, spec, membre_id } = req.body;
  if (!role) return res.status(400).json({ error: 'Rôle requis' });
  db.prepare('UPDATE users SET role=?, spec=?, membre_id=?, status=?, approved_by=? WHERE id=?')
    .run(role, spec || '', membre_id || null, 'active', req.user.username, req.params.id);
  res.json({ success: true });
});

// PUT /api/auth/reject/:id
app.put('/api/auth/reject/:id', authMiddleware, activeOnly, approverOnly, (req, res) => {
  db.prepare("UPDATE users SET status='rejected' WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

// PUT /api/auth/users/:id (admin complet)
app.put('/api/auth/users/:id', authMiddleware, activeOnly, adminOnly, (req, res) => {
  const { role, spec, membre_id } = req.body;
  db.prepare('UPDATE users SET role=?, spec=?, membre_id=? WHERE id=?').run(role, spec || '', membre_id || null, req.params.id);
  res.json({ success: true });
});

// POST /api/auth/users (admin direct create — actif tout de suite)
app.post('/api/auth/users', authMiddleware, activeOnly, adminOnly, (req, res) => {
  const { username, password, role, spec, membre_id } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Identifiant et mot de passe requis' });
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim());
  if (exists) return res.status(409).json({ error: 'Ce nom est déjà utilisé' });
  const hash = bcrypt.hashSync(password, 10);
  const id = UID();
  db.prepare('INSERT INTO users (id, username, password_hash, role, spec, membre_id, status, approved_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, username.trim(), hash, role || 'apprenti', spec || '', membre_id || null, 'active', req.user.username);
  res.json({ success: true, id });
});

// DELETE /api/auth/users/:id
app.delete('/api/auth/users/:id', authMiddleware, activeOnly, adminOnly, (req, res) => {
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// PUT /api/auth/password
app.put('/api/auth/password', authMiddleware, (req, res) => {
  const { old_password, new_password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(old_password, user.password_hash)) return res.status(401).json({ error: 'Ancien mot de passe incorrect' });
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(new_password, 10), req.user.id);
  res.json({ success: true });
});

// ============================================================
// MEMBRES
// ============================================================
app.get('/api/membres', authMiddleware, activeOnly, (req, res) => {
  res.json(db.prepare('SELECT * FROM membres ORDER BY name ASC').all());
});

app.post('/api/membres', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  const { name, rank, spec, mestre, bio, photo, status, domaine } = req.body;
  if (!name || !rank) return res.status(400).json({ error: 'Nom et grade requis' });
  const id = UID();
  db.prepare('INSERT INTO membres (id, name, rank, spec, mestre, bio, photo, status, domaine) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, name, rank, spec || '', mestre || '', bio || '', photo || '', status || 'actif', domaine || '');
  res.json({ success: true, id });
});

app.put('/api/membres/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  const { name, rank, spec, mestre, bio, photo, status, domaine } = req.body;
  // Restriction pour Maîtres de Spec : ne peuvent toucher au rang qu'au sein de leur spec
  if (!isAdmin(req.user.role)) {
    const current = db.prepare('SELECT rank FROM membres WHERE id=?').get(req.params.id);
    const promoterSpec = getSpecOfUser(req.user);
    if (current && current.rank !== rank) {
      if (HIGH_COUNCIL_RANKS.includes(rank)) {
        return res.status(403).json({ error: 'Seul le Conseil peut attribuer ce grade' });
      }
      const newRankSpec = SPEC_BY_RANK[rank];
      if (newRankSpec && newRankSpec !== promoterSpec) {
        return res.status(403).json({ error: 'Vous ne pouvez attribuer que des grades de votre spécialisation (' + promoterSpec + ')' });
      }
      const oldRankSpec = SPEC_BY_RANK[current.rank];
      if (oldRankSpec && oldRankSpec !== promoterSpec) {
        return res.status(403).json({ error: 'Ce membre n\'appartient pas à votre spécialisation (' + promoterSpec + ')' });
      }
    }
  }
  db.prepare('UPDATE membres SET name=?, rank=?, spec=?, mestre=?, bio=?, photo=?, status=?, domaine=? WHERE id=?')
    .run(name, rank, spec || '', mestre || '', bio || '', photo || '', status || 'actif', domaine || '', req.params.id);
  res.json({ success: true });
});

app.delete('/api/membres/:id', authMiddleware, activeOnly, adminOnly, (req, res) => {
  db.prepare('DELETE FROM membres WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// ANNONCES
// ============================================================
app.get('/api/annonces', authMiddleware, activeOnly, (req, res) => {
  const { section } = req.query;
  if (section) {
    res.json(db.prepare('SELECT * FROM annonces WHERE section=? ORDER BY pinned DESC, created_at DESC').all(section));
  } else {
    res.json(db.prepare('SELECT * FROM annonces ORDER BY pinned DESC, created_at DESC LIMIT 100').all());
  }
});

app.post('/api/annonces', authMiddleware, activeOnly, (req, res) => {
  const { title, contenu, section } = req.body;
  if (!title || !contenu) return res.status(400).json({ error: 'Titre et contenu requis' });
  const user = db.prepare('SELECT *, (SELECT rank FROM membres WHERE id = users.membre_id) as rank FROM users WHERE id = ?').get(req.user.id);
  const id = UID();
  db.prepare('INSERT INTO annonces (id, title, contenu, auteur, auteur_rank, section) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, title, contenu, req.user.username, user?.rank || '', section || 'general');
  res.json({ success: true, id });
});

app.put('/api/annonces/:id/pin', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('UPDATE annonces SET pinned=? WHERE id=?').run(req.body.pinned ? 1 : 0, req.params.id);
  res.json({ success: true });
});

app.delete('/api/annonces/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM annonces WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// INTERROGATIONS
// ============================================================
app.get('/api/interrogations', authMiddleware, activeOnly, (req, res) => {
  const { type } = req.query;
  if (type) {
    res.json(db.prepare('SELECT * FROM interrogations WHERE type=? ORDER BY created_at DESC').all(type));
  } else {
    res.json(db.prepare('SELECT * FROM interrogations ORDER BY created_at DESC').all());
  }
});

app.post('/api/interrogations', authMiddleware, activeOnly, (req, res) => {
  const { suspect, type, lieu, contenu, resultat } = req.body;
  if (!suspect) return res.status(400).json({ error: 'Suspect requis' });
  const id = UID();
  db.prepare('INSERT INTO interrogations (id, suspect, interrogateur, type, lieu, contenu, resultat) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, suspect, req.user.username, type || 'standard', lieu || '', contenu || '', resultat || '');
  res.json({ success: true, id });
});

app.put('/api/interrogations/:id', authMiddleware, activeOnly, (req, res) => {
  const { statut, resultat, contenu } = req.body;
  db.prepare('UPDATE interrogations SET statut=?, resultat=?, contenu=? WHERE id=?')
    .run(statut || 'ouvert', resultat || '', contenu || '', req.params.id);
  res.json({ success: true });
});

app.delete('/api/interrogations/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM interrogations WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// INFIRMERIE
// ============================================================
app.get('/api/infirmerie', authMiddleware, activeOnly, (req, res) => {
  res.json(db.prepare('SELECT * FROM infirmerie ORDER BY created_at DESC').all());
});

app.post('/api/infirmerie', authMiddleware, activeOnly, (req, res) => {
  const { patient, diagnostic, traitement, statut } = req.body;
  if (!patient) return res.status(400).json({ error: 'Patient requis' });
  const id = UID();
  db.prepare('INSERT INTO infirmerie (id, patient, medecin, diagnostic, traitement, statut) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, patient, req.user.username, diagnostic || '', traitement || '', statut || 'en-traitement');
  res.json({ success: true, id });
});

app.put('/api/infirmerie/:id', authMiddleware, activeOnly, (req, res) => {
  const { statut, diagnostic, traitement } = req.body;
  db.prepare('UPDATE infirmerie SET statut=?, diagnostic=?, traitement=? WHERE id=?')
    .run(statut || 'en-traitement', diagnostic || '', traitement || '', req.params.id);
  res.json({ success: true });
});

app.delete('/api/infirmerie/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM infirmerie WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// COURS
// ============================================================
app.get('/api/cours', authMiddleware, activeOnly, (req, res) => {
  res.json(db.prepare('SELECT * FROM cours ORDER BY created_at DESC').all());
});

app.post('/api/cours', authMiddleware, activeOnly, (req, res) => {
  const { titre, type, participants, contenu, date_cours } = req.body;
  if (!titre) return res.status(400).json({ error: 'Titre requis' });
  const id = UID();
  db.prepare('INSERT INTO cours (id, titre, instructeur, type, participants, contenu, date_cours) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, titre, req.user.username, type || 'général', participants || '', contenu || '', date_cours || '');
  res.json({ success: true, id });
});

app.delete('/api/cours/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM cours WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// MISSIONS
// ============================================================
app.get('/api/missions', authMiddleware, activeOnly, (req, res) => {
  const { spec } = req.query;
  if (spec) {
    res.json(db.prepare('SELECT * FROM missions WHERE spec=? ORDER BY created_at DESC').all(spec));
  } else {
    res.json(db.prepare('SELECT * FROM missions ORDER BY created_at DESC').all());
  }
});

app.post('/api/missions', authMiddleware, activeOnly, (req, res) => {
  const { title, type, priority, assignee, status, description, deadline, spec } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis' });
  const id = UID();
  db.prepare('INSERT INTO missions (id, title, type, priority, assignee, status, description, deadline, spec, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, title, type || 'Patrouille', priority || 'normale', assignee || '', status || 'planifiée', description || '', deadline || '', spec || 'general', req.user.username);
  res.json({ success: true, id });
});

app.put('/api/missions/:id', authMiddleware, activeOnly, (req, res) => {
  const { title, type, priority, assignee, status, description, deadline, spec } = req.body;
  db.prepare('UPDATE missions SET title=?, type=?, priority=?, assignee=?, status=?, description=?, deadline=?, spec=? WHERE id=?')
    .run(title, type, priority, assignee || '', status, description || '', deadline || '', spec || 'general', req.params.id);
  res.json({ success: true });
});

app.delete('/api/missions/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM missions WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// RAPPORTS
// ============================================================
app.get('/api/rapports', authMiddleware, activeOnly, (req, res) => {
  const { section } = req.query;
  if (section) {
    res.json(db.prepare('SELECT * FROM rapports WHERE section=? ORDER BY created_at DESC').all(section));
  } else {
    res.json(db.prepare('SELECT * FROM rapports ORDER BY created_at DESC').all());
  }
});

app.post('/api/rapports', authMiddleware, activeOnly, (req, res) => {
  const { title, type, contenu, personnes, section } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis' });
  const id = UID();
  db.prepare('INSERT INTO rapports (id, title, type, section, auteur, contenu, personnes) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, title, type || 'Mission', section || 'general', req.user.username, contenu || '', personnes || '');
  res.json({ success: true, id });
});

app.delete('/api/rapports/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM rapports WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// FORMATIONS
// ============================================================
app.get('/api/formations', authMiddleware, activeOnly, (req, res) => {
  res.json(db.prepare('SELECT * FROM formations ORDER BY created_at DESC').all());
});

app.post('/api/formations', authMiddleware, activeOnly, (req, res) => {
  const { title, type, instructeur, participants, description } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis' });
  const id = UID();
  db.prepare('INSERT INTO formations (id, title, type, instructeur, participants, description) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, title, type || 'Combat au sabre', instructeur || req.user.username, participants || '', description || '');
  res.json({ success: true, id });
});

app.delete('/api/formations/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM formations WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// POUVOIRS
// ============================================================
app.get('/api/pouvoirs', authMiddleware, activeOnly, (req, res) => {
  res.json(db.prepare('SELECT * FROM pouvoirs ORDER BY created_at DESC').all());
});

app.post('/api/pouvoirs', authMiddleware, activeOnly, (req, res) => {
  const { membre, pouvoir, niveau, validateur } = req.body;
  if (!membre || !pouvoir) return res.status(400).json({ error: 'Champs requis' });
  const id = UID();
  db.prepare('INSERT INTO pouvoirs (id, membre, pouvoir, niveau, validateur) VALUES (?, ?, ?, ?, ?)')
    .run(id, membre, pouvoir, niveau || 'Initié', validateur || '');
  res.json({ success: true, id });
});

app.delete('/api/pouvoirs/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM pouvoirs WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// TRAQUES
// ============================================================
app.get('/api/traques', authMiddleware, activeOnly, (req, res) => {
  res.json(db.prepare('SELECT * FROM traques ORDER BY created_at DESC').all());
});

app.post('/api/traques', authMiddleware, activeOnly, (req, res) => {
  const { cible, danger, responsable, description } = req.body;
  if (!cible) return res.status(400).json({ error: 'Cible requise' });
  const id = UID();
  db.prepare('INSERT INTO traques (id, cible, danger, responsable, description, status) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, cible, danger || 'Modéré', responsable || '', description || '', 'active');
  res.json({ success: true, id });
});

app.put('/api/traques/:id', authMiddleware, activeOnly, (req, res) => {
  const { status } = req.body;
  db.prepare('UPDATE traques SET status=? WHERE id=?').run(status, req.params.id);
  res.json({ success: true });
});

app.delete('/api/traques/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM traques WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// PRISON
// ============================================================
app.get('/api/prison', authMiddleware, activeOnly, (req, res) => {
  res.json(db.prepare('SELECT * FROM prison ORDER BY created_at DESC').all());
});

app.post('/api/prison', authMiddleware, activeOnly, (req, res) => {
  const { nom, arresteur, motif } = req.body;
  if (!nom) return res.status(400).json({ error: 'Nom requis' });
  const id = UID();
  db.prepare('INSERT INTO prison (id, nom, arresteur, motif, statut) VALUES (?, ?, ?, ?, ?)').run(id, nom, arresteur || '', motif || '', 'détenu');
  res.json({ success: true, id });
});

app.put('/api/prison/:id', authMiddleware, activeOnly, (req, res) => {
  db.prepare('UPDATE prison SET statut=? WHERE id=?').run(req.body.statut, req.params.id);
  res.json({ success: true });
});

app.delete('/api/prison/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM prison WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// CASIERS
// ============================================================
app.get('/api/casiers', authMiddleware, activeOnly, (req, res) => {
  const { nom } = req.query;
  if (nom) {
    res.json(db.prepare('SELECT * FROM casiers WHERE nom LIKE ? ORDER BY created_at DESC').all(`%${nom}%`));
  } else {
    res.json(db.prepare('SELECT * FROM casiers ORDER BY created_at DESC').all());
  }
});

app.post('/api/casiers', authMiddleware, activeOnly, (req, res) => {
  const { nom, gravite, infraction, sanction } = req.body;
  if (!nom) return res.status(400).json({ error: 'Nom requis' });
  const id = UID();
  db.prepare('INSERT INTO casiers (id, nom, gravite, infraction, sanction, agent) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, nom, gravite || 'Mineure', infraction || '', sanction || '', req.user.username);
  res.json({ success: true, id });
});

app.delete('/api/casiers/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM casiers WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// PROMOTIONS — accessible aux Maîtres de Spécialisation+
// ============================================================
app.get('/api/promotions', authMiddleware, activeOnly, (req, res) => {
  const { spec } = req.query;
  if (spec) {
    res.json(db.prepare('SELECT * FROM promotions WHERE spec=? ORDER BY created_at DESC').all(spec));
  } else {
    res.json(db.prepare('SELECT * FROM promotions ORDER BY created_at DESC').all());
  }
});

app.post('/api/promotions', authMiddleware, activeOnly, approverOnly, (req, res) => {
  const { membre, membre_id, rank_old, rank_new, note, spec } = req.body;
  if (!membre || !rank_new) return res.status(400).json({ error: 'Membre et nouveau grade requis' });

  // Restriction pour Maîtres de Spécialisation : seulement leur spec
  if (!isAdmin(req.user.role)) {
    const promoterSpec = getSpecOfUser(req.user);
    // Refuser les grades du Haut Conseil
    if (HIGH_COUNCIL_RANKS.includes(rank_new)) {
      return res.status(403).json({ error: 'Seul le Conseil peut promouvoir à ce grade' });
    }
    // Le nouveau grade doit être de leur spec ou neutre (apprenti/chevalier/consulaire)
    const newRankSpec = SPEC_BY_RANK[rank_new];
    if (newRankSpec && newRankSpec !== promoterSpec) {
      return res.status(403).json({ error: 'Vous ne pouvez promouvoir qu\'à des grades de votre spécialisation (' + promoterSpec + ')' });
    }
    // L'ancien grade doit aussi appartenir à leur spec ou être neutre
    if (rank_old) {
      const oldRankSpec = SPEC_BY_RANK[rank_old];
      if (oldRankSpec && oldRankSpec !== promoterSpec) {
        return res.status(403).json({ error: 'Ce membre n\'appartient pas à votre spécialisation (' + promoterSpec + ')' });
      }
    }
  }

  const id = UID();
  db.prepare('INSERT INTO promotions (id, membre, membre_id, rank_old, rank_new, promoteur, note, spec) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, membre, membre_id || '', rank_old || '', rank_new, req.user.username, note || '', spec || '');
  if (membre_id) db.prepare('UPDATE membres SET rank=? WHERE id=?').run(rank_new, membre_id);
  res.json({ success: true, id });
});

// ============================================================
// HOLOCOM
// ============================================================
app.get('/api/holocom', authMiddleware, activeOnly, (req, res) => {
  res.json(db.prepare('SELECT * FROM holocom ORDER BY created_at DESC LIMIT 100').all());
});

app.post('/api/holocom', authMiddleware, activeOnly, (req, res) => {
  const { text, type } = req.body;
  if (!text) return res.status(400).json({ error: 'Message requis' });
  const user = db.prepare('SELECT *, (SELECT rank FROM membres WHERE id = users.membre_id) as rank FROM users WHERE id = ?').get(req.user.id);
  const id = UID();
  db.prepare('INSERT INTO holocom (id, sender, sender_rank, type, text) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.user.username, user?.rank || '', type || 'info', text);
  res.json({ success: true, id });
});

app.delete('/api/holocom/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM holocom WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// PRESENTATIONS (par spécialisation)
// ============================================================
app.get('/api/presentations', authMiddleware, activeOnly, (req, res) => {
  const { spec } = req.query;
  if (spec) {
    res.json(db.prepare('SELECT * FROM presentations WHERE spec=? ORDER BY created_at DESC').all(spec));
  } else {
    res.json(db.prepare('SELECT * FROM presentations ORDER BY created_at DESC').all());
  }
});

app.post('/api/presentations', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  const { spec, titre, contenu } = req.body;
  if (!spec || !titre) return res.status(400).json({ error: 'Spécialisation et titre requis' });
  const id = UID();
  db.prepare('INSERT INTO presentations (id, spec, titre, contenu, auteur) VALUES (?, ?, ?, ?, ?)')
    .run(id, spec, titre, contenu || '', req.user.username);
  res.json({ success: true, id });
});

app.put('/api/presentations/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  const { titre, contenu } = req.body;
  db.prepare('UPDATE presentations SET titre=?, contenu=? WHERE id=?').run(titre, contenu || '', req.params.id);
  res.json({ success: true });
});

app.delete('/api/presentations/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM presentations WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// INFOS (par section)
// ============================================================
app.get('/api/infos', authMiddleware, activeOnly, (req, res) => {
  const { section } = req.query;
  if (section) {
    res.json(db.prepare('SELECT * FROM infos WHERE section=? ORDER BY created_at DESC').all(section));
  } else {
    res.json(db.prepare('SELECT * FROM infos ORDER BY created_at DESC').all());
  }
});

app.post('/api/infos', authMiddleware, activeOnly, (req, res) => {
  const { section, titre, contenu } = req.body;
  if (!section || !titre) return res.status(400).json({ error: 'Section et titre requis' });
  const id = UID();
  db.prepare('INSERT INTO infos (id, section, titre, contenu, auteur) VALUES (?, ?, ?, ?, ?)')
    .run(id, section, titre, contenu || '', req.user.username);
  res.json({ success: true, id });
});

app.delete('/api/infos/:id', authMiddleware, activeOnly, maitreOnly, (req, res) => {
  db.prepare('DELETE FROM infos WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// STATS
// ============================================================
app.get('/api/stats', authMiddleware, activeOnly, (req, res) => {
  res.json({
    membres: db.prepare('SELECT COUNT(*) as c FROM membres').get().c,
    membres_actifs: db.prepare("SELECT COUNT(*) as c FROM membres WHERE status='actif'").get().c,
    missions: db.prepare('SELECT COUNT(*) as c FROM missions').get().c,
    missions_actives: db.prepare("SELECT COUNT(*) as c FROM missions WHERE status='en-cours'").get().c,
    rapports: db.prepare('SELECT COUNT(*) as c FROM rapports').get().c,
    traques: db.prepare("SELECT COUNT(*) as c FROM traques WHERE status='active'").get().c,
    pending_users: db.prepare("SELECT COUNT(*) as c FROM users WHERE status='pending'").get().c,
  });
});

// ============================================================
// START
// ============================================================
app.listen(PORT, () => {
  console.log(`🚀 MDT Jedi démarré sur http://localhost:${PORT}`);
  console.log(`📦 Base de données: jedi.db`);
});
