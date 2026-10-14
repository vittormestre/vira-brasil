// ──────────────────────────────────────────────────────────
//  Vira Brasil · Backend do placar de votos virados
//  Node.js + Express + PostgreSQL · criptografia AES-256-GCM
// ──────────────────────────────────────────────────────────
import express from 'express';
import crypto from 'crypto';
import pg from 'pg';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

const RAW_KEY = process.env.SECRET_KEY || 'DEV-ONLY-troque-esta-chave-em-producao-por-favor';
if (!process.env.SECRET_KEY) {
  console.warn('SECRET_KEY nao definida - usando chave de desenvolvimento.');
}
const KEY = crypto.createHash('sha256').update(String(RAW_KEY)).digest();

function encrypt(texto) {
  if (texto == null || texto === '') return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(String(texto), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('base64'), tag.toString('base64'), enc.toString('base64')].join(':');
}

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
    return null;
  }
}

const { Pool } = pg;
if (!process.env.DATABASE_URL) {
  console.warn('DATABASE_URL nao definida - conecte um banco PostgreSQL no Render.');
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS registros (
      id       SERIAL PRIMARY KEY,
      uf       TEXT NOT NULL,
      nome_enc TEXT NOT NULL,
      tel_enc  TEXT,
      criado   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_uf ON registros(uf);
  `);
  console.log('Banco pronto.');
}

const UFS = new Set(['AC','AL','AP','AM','BA','CE','DF','ES','GO','MA','MT','MS','MG','PA','PB','PR','PE','PI','RJ','RN','RS','RO','RR','SC','SP','SE','TO']);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '16kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
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

const hits = new Map();
function limitar(ip, max, janelaMs) {
  const agora = Date.now();
  const reg = hits.get(ip) || { n: 0, reset: agora + janelaMs };
  if (agora > reg.reset) { reg.n = 0; reg.reset = agora + janelaMs; }
  reg.n++;
  hits.set(ip, reg);
  return reg.n <= max;
}
setInterval(() => {
  const agora = Date.now();
  for (const [ip, reg] of hits) if (agora > reg.reset) hits.delete(ip);
}, 300000);

function ipDe(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress || 'local';
}

function limpar(txt, maxLen) {
  return String(txt || '')
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .trim()
    .slice(0, maxLen);
}

async function placarAtual() {
  const r = await pool.query('SELECT uf, COUNT(*)::int AS c FROM registros GROUP BY uf');
  const porEstado = {};
  let total = 0;
  for (const row of r.rows) { porEstado[row.uf] = row.c; total += row.c; }
  return { total, porEstado };
}

app.get('/api/placar', async (req, res) => {
  if (!limitar(ipDe(req), 120, 60000)) {
    return res.status(429).json({ erro: 'Muitas requisicoes. Aguarde.' });
  }
  try {
    res.json(await placarAtual());
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao carregar o placar.' });
  }
});

app.post('/api/registrar', async (req, res) => {
  if (!limitar(ipDe(req), 15, 60000)) {
    return res.status(429).json({ erro: 'Muitos registros em pouco tempo. Aguarde um instante.' });
  }

  const uf = limpar(req.body?.uf, 2).toUpperCase();
  const nome = limpar(req.body?.nome, 120);
  const tel = limpar(req.body?.tel, 20);

  if (!UFS.has(uf)) return res.status(400).json({ erro: 'Estado invalido.' });
  if (nome.length < 3) return res.status(400).json({ erro: 'Nome muito curto.' });

  try {
    await pool.query(
      'INSERT INTO registros (uf, nome_enc, tel_enc) VALUES ($1, $2, $3)',
      [uf, encrypt(nome), tel ? encrypt(tel) : null]
    );
    res.json({ ok: true, ...(await placarAtual()) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao registrar. Tente novamente.' });
  }
});

app.get('/api/export', async (req, res) => {
  const token = process.env.ADMIN_TOKEN;
  if (!token || req.query.chave !== token) {
    return res.status(403).json({ erro: 'Acesso negado.' });
  }
  try {
    const r = await pool.query('SELECT id, uf, nome_enc, tel_enc, criado FROM registros ORDER BY id');
    const dados = r.rows.map(row => ({
      id: row.id,
      uf: row.uf,
      nome: decrypt(row.nome_enc),
      tel: decrypt(row.tel_enc),
      criado: row.criado
    }));
    res.json({ total: dados.length, registros: dados });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro na exportacao.' });
  }
});

initDB()
  .then(() => {
    app.listen(PORT, () => console.log('Vira Brasil rodando na porta ' + PORT));
  })
  .catch(err => {
    console.error('Falha ao iniciar o banco:', err);
    process.exit(1);
  });
