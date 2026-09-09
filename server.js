/**
 * Boutique TS — Serveur
 * -----------------------------------------------------------
 * Aucune dépendance externe : uniquement les modules intégrés à Node.js.
 * Même architecture que Sha'ah : fichier JSON comme base de données,
 * sessions en mémoire, jeton d'appareil pour l'app mobile.
 *
 * DEUX INTERFACES, UNE SEULE BASE DE DONNÉES :
 *  - /caisse.html  -> l'application complète (gérant/caissier). Protégée
 *                     par identifiant + mot de passe.
 *  - /scan.html    -> l'application du téléphone de la commerciale.
 *                     Jumelée une seule fois avec un jeton d'appareil
 *                     (aucun accès aux réglages, finances ou suppression).
 *
 * Quand la commerciale enregistre une vente sur son téléphone (/scan.html),
 * la requête arrive directement sur CE serveur et écrit dans le MÊME
 * data.json que la Caisse : la centralisation est réelle, pas une
 * synchronisation différée.
 *
 * Variables d'environnement utiles (toutes optionnelles) :
 *   PORT       Port d'écoute (fourni automatiquement par la plupart des
 *              hébergeurs : Render, Railway...)
 *   DATA_FILE  Emplacement du fichier de données (par défaut ./data.json)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_FILE = process.env.DATA_FILE || path.join(ROOT, 'data.json');
const BACKUP_DIR = path.join(ROOT, 'sauvegardes');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// ============================================================
// SÉCURITÉ : mots de passe, jetons, sessions
// ============================================================
function makeSalt() { return crypto.randomBytes(16).toString('hex'); }

function hashSecret(value, salt) {
  return crypto.scryptSync(String(value), salt, 64).toString('hex');
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function randomPassword(len) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  let s = '';
  for (let i = 0; i < (len || 12); i++) s += chars[crypto.randomInt(chars.length)];
  return s;
}

function fmtLog(n) {
  return Math.round(n || 0).toLocaleString('fr-FR') + ' F CFA';
}

function randomToken() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // sans caractères ambigus
  let s = '';
  for (let i = 0; i < 8; i++) s += chars[crypto.randomInt(chars.length)];
  return s;
}

function randomArticleCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
  let s = 'TS';
  for (let i = 0; i < 6; i++) s += chars[crypto.randomInt(chars.length)];
  return s;
}

// Code de suppression : 6 chiffres, facile à noter/taper, généré automatiquement
// (jamais choisi manuellement à la configuration pour éviter tout blocage à l'ouverture).
function randomDeleteCode() {
  let s = '';
  for (let i = 0; i < 6; i++) s += crypto.randomInt(10);
  return s;
}

// Sessions Caisse en mémoire (sid -> {username, expires})
const sessions = new Map();
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h

function createSession(username) {
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, { username, expires: Date.now() + SESSION_TTL_MS });
  return sid;
}
function getSession(sid) {
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() > s.expires) { sessions.delete(sid); return null; }
  return s;
}
function destroySession(sid) { sessions.delete(sid); }
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) if (now > s.expires) sessions.delete(sid);
}, 60 * 60 * 1000);

// Anti brute-force simple (connexion, code de suppression, jumelage téléphone)
const attemptCounters = new Map(); // key(ip+scope) -> {count, resetAt}
function checkRateLimit(key, max, windowMs) {
  max = max || 8; windowMs = windowMs || 15 * 60 * 1000;
  const now = Date.now();
  const rec = attemptCounters.get(key);
  if (!rec || now > rec.resetAt) {
    attemptCounters.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  rec.count++;
  return rec.count <= max;
}

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx < 0) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}
function setCookie(req, res, name, value, opts) {
  opts = opts || {};
  const isHttps = req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted;
  let str = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax`;
  if (opts.maxAge) str += `; Max-Age=${opts.maxAge}`;
  if (isHttps) str += '; Secure';
  res.setHeader('Set-Cookie', str);
}
function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; Path=/; HttpOnly; Max-Age=0`);
}

// ============================================================
// DONNÉES
// ============================================================
function defaultData() {
  return {
    articles: [],
    ventes: [],
    achats: [],
    depenses: [],
    caisseManuelle: null,
    caisseVerifications: [],
    journal: [],
    nextId: 1,
    settings: {
      setupDone: false,
      caisseUsername: '',
      caissePasswordSalt: '',
      caissePasswordHash: '',
      deleteCodeSalt: '',
      deleteCodeHash: '',
      scanToken: randomToken(),
      ai: { enabled: false, provider: 'openai', model: '', baseUrl: '', apiKey: '' }
    }
  };
}

function readData() {
  let d;
  try {
    d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    d = defaultData();
    writeData(d);
    return d;
  }
  let changed = false;
  if (!Array.isArray(d.articles)) { d.articles = []; changed = true; }
  if (!Array.isArray(d.ventes)) { d.ventes = []; changed = true; }
  if (!Array.isArray(d.achats)) { d.achats = []; changed = true; }
  if (!Array.isArray(d.depenses)) { d.depenses = []; changed = true; }
  if (!Array.isArray(d.caisseVerifications)) { d.caisseVerifications = []; changed = true; }
  if (!Array.isArray(d.journal)) { d.journal = []; changed = true; }
  if (typeof d.nextId !== 'number') { d.nextId = 1; changed = true; }
  if (d.caisseManuelle === undefined) { d.caisseManuelle = null; changed = true; }
  if (!d.settings) { d.settings = defaultData().settings; changed = true; }
  if (!d.settings.scanToken) { d.settings.scanToken = randomToken(); changed = true; }
  if (!d.settings.ai) { d.settings.ai = defaultData().settings.ai; changed = true; }
  if (typeof d.settings.setupDone !== 'boolean') { d.settings.setupDone = !!d.settings.caissePasswordHash; changed = true; }
  d.articles.forEach(a => { if (!a.code) { a.code = randomArticleCode(); changed = true; } });
  if (changed) writeData(d);
  return d;
}

// Ajoute une entrée dans le journal (audit léger : suppressions, ventes à
// perte, écarts de caisse...) utilisé par le module d'analyse intelligente.
function logJournal(data, type, detail) {
  data.journal.push({ id: data.nextId++, date: new Date().toISOString(), type, detail });
  // Garde un historique borné pour ne pas faire grossir data.json indéfiniment.
  if (data.journal.length > 2000) data.journal = data.journal.slice(-2000);
}

function writeData(obj) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj));
  fs.renameSync(tmp, DATA_FILE);
}

function backupIfNeeded() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);
    const today = new Date().toISOString().split('T')[0];
    const dest = path.join(BACKUP_DIR, `data-${today}.json`);
    if (!fs.existsSync(dest)) fs.copyFileSync(DATA_FILE, dest);
  } catch (e) {
    console.error('Sauvegarde automatique impossible :', e.message);
  }
}

// ============================================================
// UTILITAIRES HTTP
// ============================================================
function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function readBody(req, maxBytes) {
  maxBytes = maxBytes || 5 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) { reject(new Error('PAYLOAD_TOO_LARGE')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) { resolve({}); return; }
      try { resolve(JSON.parse(raw)); } catch (e) { reject(new Error('INVALID_JSON')); }
    });
    req.on('error', reject);
  });
}

function serveStatic(req, res, urlPath) {
  const safePath = urlPath === '/' ? '/index.html' : urlPath;
  const filePath = path.join(PUBLIC_DIR, safePath);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end('Interdit'); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Page introuvable : ' + urlPath);
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

function requireCaisse(req) {
  const cookies = parseCookies(req);
  return getSession(cookies.sid);
}
function requireScan(req, data) {
  const token = req.headers['x-scan-token'];
  if (!token) return false;
  return safeEqual(token, data.settings.scanToken);
}

function publicSettings(data) {
  const ai = data.settings.ai || {};
  return {
    caisseUsername: data.settings.caisseUsername, scanToken: data.settings.scanToken, setupDone: data.settings.setupDone,
    ai: { enabled: !!ai.enabled, provider: ai.provider || 'openai', model: ai.model || '', baseUrl: ai.baseUrl || '', hasKey: !!ai.apiKey }
  };
}

// Sanitize un article pour l'app Scan (pas de prix d'achat / marge : ce n'est
// pas le rôle de la commerciale de voir les coûts d'approvisionnement).
function scanArticleView(a) {
  return { id: a.id, code: a.code, nom: a.nom, vente: a.vente, stock: a.stock };
}

// Crée un enregistrement de vente (utilisé par la Caisse ET par le Scan).
// Toujours exécuté en un seul bloc synchrone (aucun await) pour rester
// atomique même si deux requêtes arrivent au même instant.
function createVente(data, payload, source) {
  const pv = Number(payload.prixvente) || 0;
  const pa = Number(payload.prixachat) || 0;
  const dc = Number(payload.depcolis) || 0;
  const qte = Math.max(1, Number(payload.quantite) || 1);
  const av = Math.min(Number(payload.avance) || 0, pv);
  const reste = Math.max(0, pv - av);
  const rec = {
    id: data.nextId++,
    date: payload.date || new Date().toISOString().split('T')[0],
    article: payload.article,
    articleCode: payload.articleCode || '',
    client: payload.client || '',
    tel: payload.tel || '',
    prixvente: pv, prixachat: pa, depcolis: dc, quantite: qte,
    marge: pv - pa - dc, avance: av, reste,
    lieu: payload.lieu || '',
    comment: payload.comment || '',
    vendeur: payload.vendeur || '',
    panierId: payload.panierId || null,
    source: source || 'caisse'
  };
  data.ventes.push(rec);
  const art = data.articles.find(a => a.nom === payload.article);
  if (art) art.stock = Math.max(0, art.stock - qte);
  if (rec.marge < 0) {
    logJournal(data, 'vente_a_perte', `Vente à perte : ${rec.article} — marge ${fmtLog(rec.marge)}`);
  }
  writeData(data);
  return rec;
}

function computeCaisseCalculee(data) {
  const totalAvances = data.ventes.reduce((s, v) => s + v.avance, 0);
  const totalAchats = data.achats.reduce((s, a) => s + a.paye, 0);
  const totalDep = data.depenses.reduce((s, d) => s + d.montant, 0);
  return totalAvances - totalAchats - totalDep;
}

// ============================================================
// MODULE D'ANALYSE INTELLIGENTE
// ------------------------------------------------------------
// Tout ce module fonctionne uniquement à partir des données déjà
// présentes (ventes, achats, articles, caisse, journal) — aucune
// dépendance à un service externe. L'IA externe (optionnelle, voir
// plus bas) vient seulement mettre en mots ces chiffres.
// ============================================================
function daysBetween(d1, d2) {
  return Math.floor((d2 - d1) / 86400000);
}

function computeStockDormant(data, seuilJours) {
  seuilJours = seuilJours || 30;
  const now = new Date();
  const lastSaleByArticle = {};
  data.ventes.forEach(v => {
    const d = new Date(v.date);
    if (isNaN(d.getTime())) return;
    if (!lastSaleByArticle[v.article] || d > lastSaleByArticle[v.article]) lastSaleByArticle[v.article] = d;
  });
  const out = [];
  data.articles.forEach(a => {
    if (!(a.stock > 0)) return;
    const last = lastSaleByArticle[a.nom];
    const jamaisVendu = !last;
    const jours = jamaisVendu ? null : daysBetween(last, now);
    if (jamaisVendu || jours > seuilJours) {
      const j = jamaisVendu ? 999 : jours;
      let remise = 0;
      if (j > 90) remise = 50; else if (j > 60) remise = 30; else if (j > 30) remise = 20;
      out.push({
        articleId: a.id, nom: a.nom, code: a.code, stock: a.stock,
        joursSansVente: jamaisVendu ? null : jours, jamaisVendu,
        prixVenteActuel: a.vente, remiseSuggeree: remise,
        prixSuggere: Math.round(a.vente * (1 - remise / 100))
      });
    }
  });
  out.sort((x, y) => (y.joursSansVente === null ? 999 : y.joursSansVente) - (x.joursSansVente === null ? 999 : x.joursSansVente));
  return out;
}

function computeEcartsCaisse(data) {
  const now = new Date();
  const recent = data.caisseVerifications.filter(v => daysBetween(new Date(v.date), now) <= 30);
  const anomalies = recent.filter(v => Math.abs(v.ecart) > 500);
  return {
    totalVerifications: recent.length,
    nbAnomalies: anomalies.length,
    recurrent: anomalies.length >= 2,
    derniere: data.caisseVerifications.length ? data.caisseVerifications[data.caisseVerifications.length - 1] : null,
    historique: recent.slice(-10).reverse()
  };
}

function computeAnomalies(data) {
  const now = new Date();
  const recent = data.journal.filter(j => daysBetween(new Date(j.date), now) <= 30);
  const ventesAPerte = recent.filter(j => j.type === 'vente_a_perte');
  const suppressions = recent.filter(j => j.type.indexOf('suppression_') === 0);
  const ecarts = recent.filter(j => j.type === 'ecart_caisse');
  return {
    ventesAPerte: ventesAPerte.slice(-15).reverse(),
    suppressions: suppressions.slice(-15).reverse(),
    ecarts: ecarts.slice(-15).reverse(),
    alerteSuppressions: suppressions.length >= 5
  };
}

function computeMiseEnAvant(data) {
  const now = new Date();
  const soldLast60 = {};
  data.ventes.forEach(v => {
    if (daysBetween(new Date(v.date), now) > 60) return;
    if (!soldLast60[v.article]) soldLast60[v.article] = { qte: 0, margeTotale: 0 };
    soldLast60[v.article].qte++;
    soldLast60[v.article].margeTotale += v.marge;
  });
  const scored = data.articles.filter(a => a.stock > 0).map(a => {
    const pctMarge = a.vente > 0 ? Math.round((a.vente - a.achat) / a.vente * 100) : 0;
    const ventes = soldLast60[a.nom] || { qte: 0, margeTotale: 0 };
    const score = pctMarge * 0.6 + Math.min(ventes.qte, 20) * 2;
    return { articleId: a.id, nom: a.nom, code: a.code, pctMarge, margeUnitaire: a.vente - a.achat, qteVendue60j: ventes.qte, stock: a.stock, score };
  });
  scored.sort((x, y) => y.score - x.score);
  return scored.slice(0, 6);
}

function computeSaisonnier(data) {
  const moisNoms = ['Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin', 'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre'];
  const byArticle = {};
  data.ventes.forEach(v => {
    const d = new Date(v.date);
    if (isNaN(d.getTime())) return;
    const m = d.getMonth();
    if (!byArticle[v.article]) byArticle[v.article] = Array(12).fill(0);
    byArticle[v.article][m] += v.prixvente;
  });
  const out = [];
  Object.entries(byArticle).forEach(([nom, mois]) => {
    const total = mois.reduce((s, x) => s + x, 0);
    if (total <= 0) return;
    let best = { start: 0, sum: -1 };
    for (let start = 0; start < 12; start++) {
      let sum = 0;
      for (let k = 0; k < 3; k++) sum += mois[(start + k) % 12];
      if (sum > best.sum) best = { start, sum };
    }
    const pctConcentration = total > 0 ? Math.round(best.sum / total * 100) : 0;
    if (pctConcentration < 40) return;
    out.push({ nom, periode: `${moisNoms[best.start]} à ${moisNoms[(best.start + 2) % 12]}`, pctConcentration, totalVentes: total });
  });
  out.sort((x, y) => y.pctConcentration - x.pctConcentration);
  return out.slice(0, 8);
}

function computeAnalytics(data) {
  return {
    stockDormant: computeStockDormant(data),
    ecartsCaisse: computeEcartsCaisse(data),
    anomalies: computeAnomalies(data),
    miseEnAvant: computeMiseEnAvant(data),
    saisonnier: computeSaisonnier(data)
  };
}

function computeRapportHebdo(data, analytics) {
  const now = new Date();
  const semaine = data.ventes.filter(v => { const j = daysBetween(new Date(v.date), now); return j >= 0 && j <= 7; });
  const semainePrec = data.ventes.filter(v => { const j = daysBetween(new Date(v.date), now); return j > 7 && j <= 14; });
  const caSemaine = semaine.reduce((s, v) => s + v.avance, 0);
  const caPrec = semainePrec.reduce((s, v) => s + v.avance, 0);
  const margeSemaine = semaine.reduce((s, v) => s + v.marge, 0);
  const evolution = caPrec > 0 ? Math.round((caSemaine - caPrec) / caPrec * 100) : null;

  const byArt = {};
  semaine.forEach(v => { byArt[v.article] = (byArt[v.article] || 0) + v.prixvente; });
  const topEntry = Object.entries(byArt).sort((a, b) => b[1] - a[1])[0];

  const ventesAPerteSemaine = analytics.anomalies.ventesAPerte.filter(j => daysBetween(new Date(j.date), now) <= 7);

  const problemes = [];
  if (evolution !== null && evolution < -15) problemes.push(`Le chiffre d'affaires a baissé de ${Math.abs(evolution)}% par rapport à la semaine précédente.`);
  if (analytics.stockDormant.length > 0) problemes.push(`${analytics.stockDormant.length} article(s) n'ont pas été vendus depuis plus de 30 jours.`);
  if (analytics.ecartsCaisse.recurrent) problemes.push(`Des écarts de caisse ont été détectés à plusieurs reprises ce mois-ci.`);
  if (ventesAPerteSemaine.length > 0) problemes.push(`${ventesAPerteSemaine.length} vente(s) à perte cette semaine.`);
  if (analytics.anomalies.alerteSuppressions) problemes.push(`Un nombre élevé de suppressions a été enregistré récemment.`);

  return {
    periode: { debut: new Date(now.getTime() - 7 * 86400000).toISOString().split('T')[0], fin: now.toISOString().split('T')[0] },
    caSemaine, caPrec, evolution, margeSemaine, nbVentes: semaine.length,
    topArticle: topEntry ? { nom: topEntry[0], montant: topEntry[1] } : null,
    problemes,
    ventesAPerteSemaine: ventesAPerteSemaine.length
  };
}

// ============================================================
// IA EXTERNE (optionnelle) — clé API fournie par l'utilisateur.
// Compatible OpenAI (et tout service compatible via une URL
// personnalisée) ou Anthropic. La clé n'est jamais renvoyée au
// client une fois enregistrée (voir publicSettings).
// ============================================================
const https = require('https');
const httpMod = require('http');

function callExternalAI(aiConfig, systemPrompt, userPrompt) {
  return new Promise((resolve, reject) => {
    const provider = aiConfig.provider || 'openai';
    let urlStr, headers, bodyObj;
    if (provider === 'anthropic') {
      urlStr = aiConfig.baseUrl || 'https://api.anthropic.com/v1/messages';
      headers = { 'x-api-key': aiConfig.apiKey, 'anthropic-version': '2023-06-01' };
      bodyObj = { model: aiConfig.model || 'claude-3-5-haiku-20241022', max_tokens: 800, system: systemPrompt, messages: [{ role: 'user', content: userPrompt }] };
    } else {
      urlStr = aiConfig.baseUrl || 'https://api.openai.com/v1/chat/completions';
      headers = { 'Authorization': 'Bearer ' + aiConfig.apiKey };
      bodyObj = { model: aiConfig.model || 'gpt-4o-mini', max_tokens: 800, messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userPrompt }] };
    }
    let u;
    try { u = new URL(urlStr); } catch (e) { return reject(new Error('URL du service IA invalide')); }
    const bodyStr = JSON.stringify(bodyObj);
    const mod = u.protocol === 'http:' ? httpMod : https;
    const request = mod.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'http:' ? 80 : 443), path: u.pathname + u.search, method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr) }, headers),
      timeout: 25000
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error('Le service IA a répondu une erreur (' + res.statusCode + ')'));
        try {
          const json = JSON.parse(raw);
          let text = '';
          if (provider === 'anthropic') text = (json.content && json.content[0] && json.content[0].text) || '';
          else text = (json.choices && json.choices[0] && json.choices[0].message && json.choices[0].message.content) || '';
          resolve((text || '').trim());
        } catch (e) { reject(new Error('Réponse du service IA illisible')); }
      });
    });
    request.on('error', () => reject(new Error('Impossible de joindre le service IA')));
    request.on('timeout', () => { request.destroy(); reject(new Error('Le service IA ne répond pas (délai dépassé)')); });
    request.write(bodyStr);
    request.end();
  });
}

function buildWeeklyPrompt(rapport, analytics) {
  const lines = [];
  lines.push(`Chiffre d'affaires encaissé cette semaine : ${fmtLog(rapport.caSemaine)} (semaine précédente : ${fmtLog(rapport.caPrec)}).`);
  if (rapport.evolution !== null) lines.push(`Évolution par rapport à la semaine précédente : ${rapport.evolution}%.`);
  lines.push(`Marge brute de la semaine : ${fmtLog(rapport.margeSemaine)} sur ${rapport.nbVentes} vente(s).`);
  if (rapport.topArticle) lines.push(`Article le plus vendu cette semaine : ${rapport.topArticle.nom} (${fmtLog(rapport.topArticle.montant)}).`);
  lines.push(`Articles en stock dormant (invendus depuis plus de 30 jours) : ${analytics.stockDormant.length}.`);
  if (analytics.stockDormant.length) lines.push('Exemples : ' + analytics.stockDormant.slice(0, 5).map(a => a.nom + (a.jamaisVendu ? ' (jamais vendu)' : ` (${a.joursSansVente}j)`)).join(', ') + '.');
  lines.push(`Ventes à perte cette semaine : ${rapport.ventesAPerteSemaine}.`);
  if (analytics.ecartsCaisse.recurrent) lines.push(`Des écarts de caisse récurrents ont été détectés ce mois-ci (${analytics.ecartsCaisse.nbAnomalies} fois).`);
  if (analytics.miseEnAvant.length) lines.push('Articles à forte marge à mettre en avant : ' + analytics.miseEnAvant.slice(0, 3).map(a => `${a.nom} (marge ${a.pctMarge}%)`).join(', ') + '.');
  if (analytics.saisonnier.length) lines.push('Tendances saisonnières observées sur l\'historique : ' + analytics.saisonnier.slice(0, 3).map(s => `${s.nom} se vend surtout de ${s.periode}`).join(', ') + '.');
  return lines.join('\n');
}

const WEEKLY_AI_SYSTEM_PROMPT = "Tu es un conseiller commercial pour une boutique en Côte d'Ivoire. On te donne un résumé chiffré de la semaine écoulée. Rédige une analyse courte (180 mots maximum) en français, structurée en 3 parties : 1) un constat honnête sur la semaine (bon ou mauvais, sans enjoliver), 2) les problèmes les plus importants à corriger en priorité, 3) des recommandations concrètes et actionnables (quels produits mettre en avant, lesquels solder ou à quel prix, quand). Style direct, concret, sans jargon, adapté à un commerçant.";

// ============================================================
// SERVEUR
// ============================================================
const server = http.createServer(async (req, res) => {
  try {
    const parsedUrl = new URL(req.url, 'http://localhost');
    const urlPath = decodeURIComponent(parsedUrl.pathname);
    const ip = req.socket.remoteAddress || 'inconnu';

    // ---------- SESSION / AUTHENTIFICATION CAISSE ----------
    if (urlPath === '/api/session' && req.method === 'GET') {
      const data = readData();
      const s = requireCaisse(req);
      return sendJSON(res, 200, { loggedIn: !!s, username: s ? s.username : null, setupDone: data.settings.setupDone });
    }

    if (urlPath === '/api/setup' && req.method === 'POST') {
      const data = readData();
      if (data.settings.setupDone) return sendJSON(res, 403, { ok: false, error: 'La configuration a déjà été effectuée.' });
      const body = await readBody(req);
      const username = (body.username || '').trim();
      const password = body.password || '';
      if (!username || password.length < 4) {
        return sendJSON(res, 400, { ok: false, error: 'Identifiant et mot de passe (min. 4 caractères) requis.' });
      }
      const pwSalt = makeSalt();
      const codeSalt = makeSalt();
      // Le code de suppression est TOUJOURS généré automatiquement (jamais saisi
      // manuellement) pour qu'un oubli/mauvaise saisie ne bloque jamais l'ouverture
      // de l'application. Il est renvoyé une seule fois dans cette réponse.
      const deleteCode = randomDeleteCode();
      data.settings.caisseUsername = username;
      data.settings.caissePasswordSalt = pwSalt;
      data.settings.caissePasswordHash = hashSecret(password, pwSalt);
      data.settings.deleteCodeSalt = codeSalt;
      data.settings.deleteCodeHash = hashSecret(deleteCode, codeSalt);
      data.settings.setupDone = true;
      writeData(data);
      const sid = createSession(username);
      setCookie(req, res, 'sid', sid, { maxAge: 12 * 60 * 60 });
      return sendJSON(res, 200, { ok: true, username, deleteCode });
    }

    if (urlPath === '/api/login' && req.method === 'POST') {
      if (!checkRateLimit('login:' + ip, 8, 15 * 60 * 1000)) {
        return sendJSON(res, 429, { ok: false, error: 'Trop de tentatives. Réessayez dans quelques minutes.' });
      }
      const data = readData();
      const body = await readBody(req);
      const { username, password } = body || {};
      if (!username || !password) return sendJSON(res, 400, { ok: false, error: 'Identifiants manquants' });
      const validUser = data.settings.caisseUsername && safeEqual(username, data.settings.caisseUsername);
      const hash = hashSecret(password, data.settings.caissePasswordSalt || 'x');
      const ok = validUser && safeEqual(hash, data.settings.caissePasswordHash || '');
      if (!ok) return sendJSON(res, 401, { ok: false, error: 'Identifiant ou mot de passe incorrect' });
      const sid = createSession(data.settings.caisseUsername);
      setCookie(req, res, 'sid', sid, { maxAge: 12 * 60 * 60 });
      return sendJSON(res, 200, { ok: true, username: data.settings.caisseUsername });
    }

    if (urlPath === '/api/logout' && req.method === 'POST') {
      const cookies = parseCookies(req);
      if (cookies.sid) destroySession(cookies.sid);
      clearCookie(res, 'sid');
      return sendJSON(res, 200, { ok: true });
    }

    if (urlPath === '/api/settings/password' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req);
      const { currentPassword, newUsername, newPassword } = body || {};
      const curHash = hashSecret(currentPassword || '', data.settings.caissePasswordSalt);
      if (!safeEqual(curHash, data.settings.caissePasswordHash)) return sendJSON(res, 401, { ok: false, error: 'Mot de passe actuel incorrect' });
      if (newUsername && newUsername.trim()) data.settings.caisseUsername = newUsername.trim();
      if (newPassword) {
        if (newPassword.length < 4) return sendJSON(res, 400, { ok: false, error: 'Le nouveau mot de passe doit faire au moins 4 caractères' });
        const salt = makeSalt();
        data.settings.caissePasswordSalt = salt;
        data.settings.caissePasswordHash = hashSecret(newPassword, salt);
      }
      writeData(data);
      return sendJSON(res, 200, { ok: true, username: data.settings.caisseUsername });
    }

    if (urlPath === '/api/settings/delete-code' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req);
      const { currentCode, newCode } = body || {};
      const curHash = hashSecret(currentCode || '', data.settings.deleteCodeSalt);
      if (!safeEqual(curHash, data.settings.deleteCodeHash)) return sendJSON(res, 401, { ok: false, error: 'Code actuel incorrect' });
      if (!newCode || newCode.length < 4) return sendJSON(res, 400, { ok: false, error: 'Le nouveau code doit faire au moins 4 caractères' });
      const salt = makeSalt();
      data.settings.deleteCodeSalt = salt;
      data.settings.deleteCodeHash = hashSecret(newCode, salt);
      writeData(data);
      return sendJSON(res, 200, { ok: true });
    }

    // Code de suppression oublié : réinitialisation via le mot de passe de
    // connexion (pas besoin de connaître l'ancien code). Un nouveau code
    // aléatoire est généré et renvoyé une seule fois.
    if (urlPath === '/api/settings/delete-code/reset' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      if (!checkRateLimit('delreset:' + ip, 5, 15 * 60 * 1000)) return sendJSON(res, 429, { ok: false, error: 'Trop de tentatives. Réessayez dans quelques minutes.' });
      const body = await readBody(req);
      const curHash = hashSecret(body.password || '', data.settings.caissePasswordSalt);
      if (!safeEqual(curHash, data.settings.caissePasswordHash)) return sendJSON(res, 401, { ok: false, error: 'Mot de passe incorrect' });
      const newCode = randomDeleteCode();
      const salt = makeSalt();
      data.settings.deleteCodeSalt = salt;
      data.settings.deleteCodeHash = hashSecret(newCode, salt);
      writeData(data);
      return sendJSON(res, 200, { ok: true, deleteCode: newCode });
    }

    if (urlPath === '/api/settings/scan-token/regenerate' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      data.settings.scanToken = randomToken();
      writeData(data);
      return sendJSON(res, 200, { ok: true, scanToken: data.settings.scanToken });
    }

    // ---------- BOOTSTRAP (chargement complet pour la Caisse) ----------
    if (urlPath === '/api/bootstrap' && req.method === 'GET') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      return sendJSON(res, 200, {
        ok: true,
        articles: data.articles, ventes: data.ventes, achats: data.achats,
        depenses: data.depenses, caisseManuelle: data.caisseManuelle,
        settings: publicSettings(data)
      });
    }

    // ---------- ARTICLES ----------
    if (urlPath === '/api/articles' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req);
      const nom = (body.nom || '').trim();
      const achat = Number(body.achat) || 0;
      const vente = Number(body.vente) || 0;
      if (!nom || !achat || !vente) return sendJSON(res, 400, { ok: false, error: "Nom, prix d'achat et prix de vente requis" });
      if (data.articles.some(a => a.nom.toLowerCase() === nom.toLowerCase())) return sendJSON(res, 409, { ok: false, error: 'Un article portant ce nom existe déjà' });
      let code = (body.code || '').trim().toUpperCase() || randomArticleCode();
      if (data.articles.some(a => a.code === code)) return sendJSON(res, 409, { ok: false, error: 'Ce code produit est déjà utilisé' });
      const rec = { id: data.nextId++, code, nom, achat, vente, stock: Number(body.stock) || 0, seuil: Number(body.seuil) || 5 };
      data.articles.push(rec);
      writeData(data);
      return sendJSON(res, 200, { ok: true, article: rec });
    }

    if (urlPath.startsWith('/api/articles/') && urlPath.endsWith('') && req.method === 'PUT') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const id = Number(urlPath.split('/')[3]);
      const art = data.articles.find(a => a.id === id);
      if (!art) return sendJSON(res, 404, { ok: false, error: 'Article introuvable' });
      const body = await readBody(req);
      const nom = (body.nom || '').trim();
      if (!nom) return sendJSON(res, 400, { ok: false, error: 'Nom requis' });
      if (data.articles.some(a => a.id !== id && a.nom.toLowerCase() === nom.toLowerCase())) return sendJSON(res, 409, { ok: false, error: 'Un article portant ce nom existe déjà' });
      const ancienNom = art.nom;
      art.nom = nom;
      art.achat = Number(body.achat) || 0;
      art.vente = Number(body.vente) || 0;
      art.stock = Number(body.stock) || 0;
      art.seuil = Number(body.seuil) || 5;
      if (ancienNom !== nom) {
        data.ventes.forEach(v => { if (v.article === ancienNom) v.article = nom; });
        data.achats.forEach(a => { if (a.article === ancienNom) a.article = nom; });
      }
      writeData(data);
      return sendJSON(res, 200, { ok: true, article: art });
    }

    if (urlPath.match(/^\/api\/articles\/\d+\/delete$/) && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      if (!checkRateLimit('delcode:' + ip, 3, 30 * 1000)) return sendJSON(res, 429, { ok: false, error: 'Trop de tentatives. Réessayez dans 30 secondes.' });
      const id = Number(urlPath.split('/')[3]);
      const body = await readBody(req);
      const hash = hashSecret(body.code || '', data.settings.deleteCodeSalt);
      if (!safeEqual(hash, data.settings.deleteCodeHash)) return sendJSON(res, 403, { ok: false, error: 'Code de suppression incorrect' });
      const artDel = data.articles.find(a => a.id === id);
      data.articles = data.articles.filter(a => a.id !== id);
      logJournal(data, 'suppression_article', artDel ? `Article supprimé : ${artDel.nom} (${artDel.code})` : `Article #${id} supprimé`);
      writeData(data);
      return sendJSON(res, 200, { ok: true });
    }

    // ---------- VENTES ----------
    if (urlPath === '/api/ventes' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req);
      if (!body.date || !body.article || !body.prixvente) return sendJSON(res, 400, { ok: false, error: 'Champs obligatoires manquants' });
      const rec = createVente(data, body, 'caisse');
      return sendJSON(res, 200, { ok: true, vente: rec });
    }

    if (urlPath.match(/^\/api\/ventes\/\d+$/) && req.method === 'PUT') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const id = Number(urlPath.split('/')[3]);
      const v = data.ventes.find(x => x.id === id);
      if (!v) return sendJSON(res, 404, { ok: false, error: 'Vente introuvable' });
      const body = await readBody(req);
      const pv = Number(body.prixvente) || 0;
      const pa = Number(body.prixachat) || 0;
      const dc = Number(body.depcolis) || 0;
      const av = Math.min(Number(body.avance) || 0, pv);
      Object.assign(v, {
        date: body.date || v.date, article: body.article || v.article,
        client: body.client || '', tel: body.tel || '',
        prixvente: pv, prixachat: pa, depcolis: dc, marge: pv - pa - dc,
        avance: av, reste: Math.max(0, pv - av),
        lieu: body.lieu || '', comment: body.comment || ''
      });
      writeData(data);
      return sendJSON(res, 200, { ok: true, vente: v });
    }

    if (urlPath.match(/^\/api\/ventes\/\d+\/payment$/) && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const id = Number(urlPath.split('/')[3]);
      const v = data.ventes.find(x => x.id === id);
      if (!v) return sendJSON(res, 404, { ok: false, error: 'Vente introuvable' });
      const body = await readBody(req);
      const montant = Number(body.montant) || 0;
      if (montant <= 0 || montant > v.reste) return sendJSON(res, 400, { ok: false, error: 'Montant invalide' });
      v.avance += montant;
      v.reste = Math.max(0, v.prixvente - v.avance);
      writeData(data);
      return sendJSON(res, 200, { ok: true, vente: v });
    }

    if (urlPath.match(/^\/api\/ventes\/\d+\/delete$/) && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      if (!checkRateLimit('delcode:' + ip, 3, 30 * 1000)) return sendJSON(res, 429, { ok: false, error: 'Trop de tentatives. Réessayez dans 30 secondes.' });
      const id = Number(urlPath.split('/')[3]);
      const body = await readBody(req);
      const hash = hashSecret(body.code || '', data.settings.deleteCodeSalt);
      if (!safeEqual(hash, data.settings.deleteCodeHash)) return sendJSON(res, 403, { ok: false, error: 'Code de suppression incorrect' });
      const venteDel = data.ventes.find(v => v.id === id);
      data.ventes = data.ventes.filter(v => v.id !== id);
      logJournal(data, 'suppression_vente', venteDel ? `Vente supprimée : ${venteDel.article} (${fmtLog(venteDel.prixvente)})` : `Vente #${id} supprimée`);
      writeData(data);
      return sendJSON(res, 200, { ok: true });
    }

    // ---------- ACHATS ----------
    if (urlPath === '/api/achats' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req);
      if (!body.date || !body.fournisseur || !body.article || !body.quantite || !body.prixunit) {
        return sendJSON(res, 400, { ok: false, error: 'Champs obligatoires manquants' });
      }
      const q = Number(body.quantite) || 0;
      const pu = Number(body.prixunit) || 0;
      const tr = Number(body.transport) || 0;
      const total = q * pu + tr;
      const paye = Number(body.paye) || 0;
      const rec = {
        id: data.nextId++, date: body.date, fournisseur: body.fournisseur.trim(), article: body.article,
        quantite: q, prixunit: pu, transport: tr, total, paye, reste: Math.max(0, total - paye),
        note: body.note || ''
      };
      data.achats.push(rec);
      const art = data.articles.find(a => a.nom === body.article);
      if (art) art.stock += q;
      writeData(data);
      return sendJSON(res, 200, { ok: true, achat: rec });
    }

    if (urlPath.match(/^\/api\/achats\/\d+\/delete$/) && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      if (!checkRateLimit('delcode:' + ip, 3, 30 * 1000)) return sendJSON(res, 429, { ok: false, error: 'Trop de tentatives. Réessayez dans 30 secondes.' });
      const id = Number(urlPath.split('/')[3]);
      const body = await readBody(req);
      if (!safeEqual(hashSecret(body.code || '', data.settings.deleteCodeSalt), data.settings.deleteCodeHash)) return sendJSON(res, 403, { ok: false, error: 'Code de suppression incorrect' });
      const achatDel = data.achats.find(a => a.id === id);
      data.achats = data.achats.filter(a => a.id !== id);
      logJournal(data, 'suppression_achat', achatDel ? `Achat supprimé : ${achatDel.article} × ${achatDel.quantite} (${achatDel.fournisseur})` : `Achat #${id} supprimé`);
      writeData(data);
      return sendJSON(res, 200, { ok: true });
    }

    // ---------- DÉPENSES ----------
    if (urlPath === '/api/depenses' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req);
      const libelle = (body.libelle || '').trim();
      const montant = Number(body.montant) || 0;
      if (!libelle || !montant) return sendJSON(res, 400, { ok: false, error: 'Libellé et montant requis' });
      const rec = { id: data.nextId++, type: body.type || 'fixe', libelle, montant, mois: body.mois || '', note: body.note || '' };
      data.depenses.push(rec);
      writeData(data);
      return sendJSON(res, 200, { ok: true, depense: rec });
    }

    if (urlPath.match(/^\/api\/depenses\/\d+\/delete$/) && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const id = Number(urlPath.split('/')[3]);
      data.depenses = data.depenses.filter(d => d.id !== id);
      writeData(data);
      return sendJSON(res, 200, { ok: true });
    }

    // ---------- CAISSE MANUELLE ----------
    if (urlPath === '/api/caisse-manuelle' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req);
      const v = Number(body.montant);
      if (isNaN(v)) return sendJSON(res, 400, { ok: false, error: 'Montant invalide' });
      data.caisseManuelle = v;
      const calc = computeCaisseCalculee(data);
      const ecart = v - calc;
      data.caisseVerifications.push({ date: new Date().toISOString(), calc, reel: v, ecart });
      if (data.caisseVerifications.length > 500) data.caisseVerifications = data.caisseVerifications.slice(-500);
      if (Math.abs(ecart) > 1) logJournal(data, 'ecart_caisse', `Écart de caisse détecté : ${fmtLog(ecart)} (calculé ${fmtLog(calc)}, compté ${fmtLog(v)})`);
      writeData(data);
      return sendJSON(res, 200, { ok: true });
    }

    // ---------- ANALYSE INTELLIGENTE ----------
    if (urlPath === '/api/analytics' && req.method === 'GET') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      return sendJSON(res, 200, { ok: true, analytics: computeAnalytics(data) });
    }

    if (urlPath === '/api/analytics/weekly-report' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const analytics = computeAnalytics(data);
      const rapport = computeRapportHebdo(data, analytics);
      const ai = data.settings.ai || {};
      if (ai.enabled && ai.apiKey) {
        try {
          const resume = await callExternalAI(ai, WEEKLY_AI_SYSTEM_PROMPT, buildWeeklyPrompt(rapport, analytics));
          return sendJSON(res, 200, { ok: true, rapport, resumeIA: resume, source: 'ia' });
        } catch (e) {
          return sendJSON(res, 200, { ok: true, rapport, resumeIA: null, source: 'regle', avertissementIA: e.message });
        }
      }
      return sendJSON(res, 200, { ok: true, rapport, resumeIA: null, source: 'regle' });
    }

    // ---------- RÉGLAGES IA EXTERNE ----------
    if (urlPath === '/api/settings/ai' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const body = await readBody(req);
      const ai = data.settings.ai || {};
      if (typeof body.enabled === 'boolean') ai.enabled = body.enabled;
      if (body.provider) ai.provider = body.provider;
      if (typeof body.model === 'string') ai.model = body.model.trim();
      if (typeof body.baseUrl === 'string') ai.baseUrl = body.baseUrl.trim();
      if (typeof body.apiKey === 'string' && body.apiKey.trim()) ai.apiKey = body.apiKey.trim();
      if (body.clearKey) ai.apiKey = '';
      data.settings.ai = ai;
      writeData(data);
      return sendJSON(res, 200, { ok: true, settings: publicSettings(data) });
    }

    if (urlPath === '/api/settings/ai/test' && req.method === 'POST') {
      const data = readData();
      if (!requireCaisse(req)) return sendJSON(res, 401, { ok: false, error: 'Non authentifié' });
      const ai = data.settings.ai || {};
      if (!ai.apiKey) return sendJSON(res, 400, { ok: false, error: 'Aucune clé API enregistrée' });
      try {
        const reply = await callExternalAI(ai, "Réponds uniquement par le mot OK.", "Confirme la connexion.");
        return sendJSON(res, 200, { ok: true, reply });
      } catch (e) {
        return sendJSON(res, 200, { ok: false, error: e.message });
      }
    }

    // ---------- APP SCAN (téléphone de la commerciale) ----------
    if (urlPath === '/api/scan/pair' && req.method === 'POST') {
      if (!checkRateLimit('pair:' + ip, 15, 15 * 60 * 1000)) return sendJSON(res, 429, { ok: false, error: 'Trop de tentatives. Réessayez plus tard.' });
      const data = readData();
      const body = await readBody(req);
      const token = (body.token || '').trim().toUpperCase();
      if (!token) return sendJSON(res, 400, { ok: false, error: 'Jeton requis' });
      if (!data.settings.setupDone) return sendJSON(res, 409, { ok: false, error: "La Caisse n'a pas encore été configurée." });
      if (!safeEqual(token, data.settings.scanToken)) return sendJSON(res, 401, { ok: false, error: 'Jeton incorrect. Demandez-le au gérant (Réglages > Application Scan).' });
      return sendJSON(res, 200, { ok: true, boutique: data.settings.caisseUsername ? 'Boutique TS' : 'Boutique TS' });
    }

    if (urlPath === '/api/scan/lookup' && req.method === 'GET') {
      const data = readData();
      if (!requireScan(req, data)) return sendJSON(res, 401, { ok: false, error: 'Appareil non jumelé' });
      const code = (parsedUrl.searchParams.get('code') || '').trim();
      const art = data.articles.find(a => a.code === code);
      if (!art) return sendJSON(res, 404, { ok: false, error: 'Aucun article ne correspond à ce code.' });
      return sendJSON(res, 200, { ok: true, article: scanArticleView(art) });
    }

    if (urlPath === '/api/scan/vente' && req.method === 'POST') {
      if (!checkRateLimit('scanvente:' + ip, 60, 5 * 60 * 1000)) return sendJSON(res, 429, { ok: false, error: 'Trop de requêtes. Patientez un instant.' });
      const data = readData();
      if (!requireScan(req, data)) return sendJSON(res, 401, { ok: false, error: 'Appareil non jumelé' });
      const body = await readBody(req);
      const art = data.articles.find(a => a.code === (body.code || '').trim());
      if (!art) return sendJSON(res, 404, { ok: false, error: 'Article introuvable' });
      const pv = Number(body.prixvente) || art.vente;
      const rec = createVente(data, {
        date: new Date().toISOString().split('T')[0],
        article: art.nom, articleCode: art.code,
        client: body.client || '', tel: body.tel || '',
        prixvente: pv, prixachat: art.achat, depcolis: 0,
        avance: body.avance, lieu: body.lieu || '', comment: body.comment || '',
        vendeur: body.vendeur || ''
      }, 'scan');
      return sendJSON(res, 200, { ok: true, vente: rec, stockRestant: art.stock });
    }

    // Vente d'un panier complet (plusieurs articles différents, quantités
    // variables) enregistrée en une seule requête, en tout-ou-rien : soit
    // tous les articles existent et toutes les lignes sont créées, soit rien
    // n'est écrit. L'avance totale est répartie ligne par ligne (les
    // premiers articles du panier sont considérés payés en premier).
    if (urlPath === '/api/scan/panier' && req.method === 'POST') {
      if (!checkRateLimit('scanvente:' + ip, 60, 5 * 60 * 1000)) return sendJSON(res, 429, { ok: false, error: 'Trop de requêtes. Patientez un instant.' });
      const data = readData();
      if (!requireScan(req, data)) return sendJSON(res, 401, { ok: false, error: 'Appareil non jumelé' });
      const body = await readBody(req);
      const items = Array.isArray(body.items) ? body.items : [];
      if (!items.length) return sendJSON(res, 400, { ok: false, error: 'Le panier est vide' });
      if (items.length > 50) return sendJSON(res, 400, { ok: false, error: 'Panier trop volumineux (50 articles maximum)' });

      const resolved = [];
      for (const it of items) {
        const art = data.articles.find(a => a.code === String(it.code || '').trim());
        if (!art) return sendJSON(res, 404, { ok: false, error: `Article introuvable pour le code ${it.code}` });
        const qte = Math.max(1, Number(it.quantite) || 1);
        const unitPrice = Number(it.prixvente) || art.vente;
        resolved.push({ art, qte, unitPrice, lineTotal: unitPrice * qte });
      }

      const grandTotal = resolved.reduce((s, r) => s + r.lineTotal, 0);
      let avanceRestante = Math.min(Number(body.avance) || 0, grandTotal);
      const panierId = crypto.randomBytes(6).toString('hex');
      const dateStr = new Date().toISOString().split('T')[0];
      const ventesCreated = [];
      for (const r of resolved) {
        const ligneAvance = Math.min(avanceRestante, r.lineTotal);
        avanceRestante -= ligneAvance;
        const rec = createVente(data, {
          date: dateStr, article: r.art.nom, articleCode: r.art.code,
          client: body.client || '', tel: body.tel || '',
          prixvente: r.lineTotal, prixachat: r.art.achat * r.qte, depcolis: 0,
          avance: ligneAvance, lieu: body.lieu || '', comment: body.comment || '',
          vendeur: body.vendeur || '', quantite: r.qte, panierId
        }, 'scan');
        ventesCreated.push(rec);
      }
      const avanceTotal = ventesCreated.reduce((s, v) => s + v.avance, 0);
      return sendJSON(res, 200, { ok: true, panierId, ventes: ventesCreated, total: grandTotal, avanceTotal, resteTotal: grandTotal - avanceTotal });
    }

    if (urlPath === '/api/scan/today' && req.method === 'GET') {
      const data = readData();
      if (!requireScan(req, data)) return sendJSON(res, 401, { ok: false, error: 'Appareil non jumelé' });
      const today = new Date().toISOString().split('T')[0];
      const ventes = data.ventes.filter(v => v.source === 'scan' && v.date === today)
        .sort((a, b) => b.id - a.id)
        .map(v => ({ id: v.id, article: v.article, prixvente: v.prixvente, avance: v.avance, reste: v.reste, client: v.client, vendeur: v.vendeur }));
      const total = ventes.reduce((s, v) => s + v.avance, 0);
      return sendJSON(res, 200, { ok: true, ventes, total });
    }

    // ---------- Fichiers statiques ----------
    if (req.method === 'GET') return serveStatic(req, res, urlPath);

    res.writeHead(405);
    res.end('Méthode non autorisée');
  } catch (e) {
    if (e.message === 'PAYLOAD_TOO_LARGE') return sendJSON(res, 413, { ok: false, error: 'Requête trop volumineuse' });
    if (e.message === 'INVALID_JSON') return sendJSON(res, 400, { ok: false, error: 'Données invalides' });
    console.error(e);
    sendJSON(res, 500, { ok: false, error: 'Erreur serveur' });
  }
});

server.listen(PORT, () => {
  const data = readData();
  backupIfNeeded();
  console.log('');
  console.log('==========================================================');
  console.log('   Boutique TS — le serveur est démarré (port ' + PORT + ')');
  console.log('   Ouvrez http://localhost:' + PORT + ' sur cet ordinateur');
  console.log('==========================================================');
  if (!data.settings.setupDone) {
    console.log('   Première utilisation : ouvrez /caisse.html pour créer');
    console.log('   votre identifiant, votre mot de passe et le code de');
    console.log('   suppression secret.');
  } else {
    console.log('   Jeton de jumelage de l\'app Scan (téléphone) : ' + data.settings.scanToken);
    console.log('   (aussi visible dans Réglages > Application Scan)');
  }
  console.log('==========================================================');
  console.log('');
});
