// ──────────────────────────────────────────────────────────
//  Vira Brasil · Backend do placar de votos virados
//  Node.js + Express + SQLite · com criptografia AES-256-GCM
// ──────────────────────────────────────────────────────────
import express from 'express';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

// ──────────────────────────────────────────────────────────
//  1) CHAVE DE CRIPTOGRAFIA
//  A chave vem da variável de ambiente SECRET_KEY (defina no Render).
//  Deve ser uma string longa e aleatória. Em dev, uma é derivada,
//  mas em PRODUÇÃO você DEVE definir SECRET_KEY própria.
// ──────────────────────────────────────────────────────────
const RAW_KEY = process.env.SECRET_KEY || 'DEV-ONLY-troque-esta-chave-em-producao-por-favor';
if (!process.env.SECRET_KEY) {
  console.warn('⚠️  SECRET_KEY não definida — usando chave de desenvolvimento. NÃO use assim em produção!');
}
// Deriva uma chave de 32 bytes (256 bits) a partir do segredo
const KEY = crypto.createHash('sha256').update(String(RAW_KEY)).digest();

// Criptografa um texto → retorna "iv:tag:dados" em base64
function encrypt(texto) {
  if (texto == null || texto === '') return null;
  const iv = crypto.randomBytes(12); // nonce de 96 bits (padrão GCM)
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(String(texto), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('base64'), tag.toString('base64'), enc.toString('base64')].join(':');
}

// Descriptografa "iv:tag:dados" → texto original (uso administrativo)
function decrypt(blob) {
  if (!blob) return null;
  try {
    const [ivB64, tagB64, dataB64] = String(blob).split(':');
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const data = Buffer.from(dataB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch {
    return null; // dado adulterado ou chave errada
  }
}

// ──────────────────────────────────────────────────────────
//  2) BANCO DE DADOS
// ──────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || join(__dirname, 'votos.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS registros (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    uf       TEXT NOT NULL,
    nome_enc TEXT NOT NULL,   -- nome criptografado (AES-256-GCM)
    tel_enc  TEXT,            -- telefone criptografado
    criado   TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_uf ON registros(uf);
`);

const UFS = new Set(['AC','AL','AP','AM','BA','CE','DF','ES','GO','MA','MT','MS','MG','PA','PB','PR','PE','PI','RJ','RN','RS','RO','RR','SC','SP','SE','TO']);

const insert = db.prepare('INSERT INTO registros (uf, nome_enc, tel_enc) VALUES (?, ?, ?)');
const totalStmt = db.prepare('SELECT COUNT(*) AS total FROM registros');
const porEstadoStmt = db.prepare('SELECT uf, COUNT(*) AS c FROM registros GROUP BY uf ORDER BY c DESC');

// ──────────────────────────────────────────────────────────
//  3) APP + HEADERS DE SEGURANÇA
// ──────────────────────────────────────────────────────────
const app = express();
app.disable('x-powered-by');          // não revela que é Express
app.set('trust proxy', 1);            // confia no proxy do Render (para o IP real)
app.use(express.json({ limit: '16kb' }));

// Headers de segurança aplicados a todas as respostas
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');                 // impede embutir o site em iframe (anti-clickjacking)
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'); // força HTTPS
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "img-src 'self' https://commons.wikimedia.org https://upload.wikimedia.org https://thumb.wikimedia.org data:; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " +
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
    "script-src 'self' 'unsafe-inline'; " +
    "connect-src 'self'; " +
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  );
  next();
});

app.use(express.static(__dirname));

// ──────────────────────────────────────────────────────────
//  4) RATE LIMITING (anti-flood)
// ──────────────────────────────────────────────────────────
const hits = new Map();
function limitar(ip, max, janelaMs) {
  const agora = Date.now();
  const reg = hits.get(ip) || { n: 0, reset: agora + janelaMs };
  if (agora > reg.reset) { reg.n = 0; reg.reset = agora + janelaMs; }
  reg.n++;
  hits.set(ip, reg);
  return reg.n <= max;
}
// limpeza periódica da memória
setInterval(() => {
  const agora = Date.now();
  for (const [ip, reg] of hits) if (agora > reg.reset) hits.delete(ip);
}, 300000);

function ipDe(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress || 'local';
}

// Sanitiza texto: remove caracteres de controle e normaliza
function limpar(txt, maxLen) {
  return String(txt || '')
    .replace(/[\u0000-\u001F\u007F]/g, '') // remove caracteres de controle
    .trim()
    .slice(0, maxLen);
}

function placarAtual() {
  const total = totalStmt.get().total;
  const porEstado = {};
  for (const row of porEstadoStmt.all()) porEstado[row.uf] = row.c;
  return { total, porEstado };
}

// ──────────────────────────────────────────────────────────
//  5) ROTAS
// ──────────────────────────────────────────────────────────

// GET /api/placar → números públicos (nunca expõe dados pessoais)
app.get('/api/placar', (req, res) => {
  if (!limitar(ipDe(req), 120, 60000)) {
    return res.status(429).json({ erro: 'Muitas requisições. Aguarde.' });
  }
  res.json(placarAtual());
});

// POST /api/registrar → registra 1 voto (dados pessoais criptografados)
app.post('/api/registrar', (req, res) => {
  if (!limitar(ipDe(req), 15, 60000)) {
    return res.status(429).json({ erro: 'Muitos registros em pouco tempo. Aguarde um instante.' });
  }

  const uf = limpar(req.body?.uf, 2).toUpperCase();
  const nome = limpar(req.body?.nome, 120);
  const tel = limpar(req.body?.tel, 20);

  if (!UFS.has(uf)) return res.status(400).json({ erro: 'Estado inválido.' });
  if (nome.length < 3) return res.status(400).json({ erro: 'Nome muito curto.' });

  // CRIPTOGRAFA antes de salvar — o banco nunca guarda nome/telefone em texto puro
  insert.run(uf, encrypt(nome), tel ? encrypt(tel) : null);

  res.json({ ok: true, ...placarAtual() });
});

// GET /api/export?chave=... → exportação administrativa (descriptografada)
// Protegida por ADMIN_TOKEN. Use só você, para auditar os registros.
app.get('/api/export', (req, res) => {
  const token = process.env.ADMIN_TOKEN;
  if (!token || req.query.chave !== token) {
    return res.status(403).json({ erro: 'Acesso negado.' });
  }
  const rows = db.prepare('SELECT id, uf, nome_enc, tel_enc, criado FROM registros ORDER BY id').all();
  const dados = rows.map(r => ({
    id: r.id,
    uf: r.uf,
    nome: decrypt(r.nome_enc),
    tel: decrypt(r.tel_enc),
    criado: r.criado
  }));
  res.json({ total: dados.length, registros: dados });
});

app.listen(PORT, () => {
  console.log(`✅ Vira Brasil rodando em http://localhost:${PORT}`);
});
