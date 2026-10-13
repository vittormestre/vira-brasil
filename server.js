// ──────────────────────────────────────────────────────────
//  Vira Brasil · Backend do placar de votos virados
//  Node.js puro (sem dependências nativas) · criptografia AES-256-GCM
//  Armazenamento em arquivo JSON (dados pessoais criptografados)
// ──────────────────────────────────────────────────────────
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

// ──────────────────────────────────────────────────────────
//  1) CHAVE DE CRIPTOGRAFIA (via SECRET_KEY no Render)
// ──────────────────────────────────────────────────────────
const RAW_KEY = process.env.SECRET_KEY || 'DEV-ONLY-troque-esta-chave-em-producao-por-favor';
if (!process.env.SECRET_KEY) {
  console.warn('⚠️  SECRET_KEY não definida — usando chave de desenvolvimento. NÃO use assim em produção!');
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

// ──────────────────────────────────────────────────────────
//  2) ARMAZENAMENTO (arquivo JSON) — sem dependências nativas
// ──────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || join(__dirname, 'votos.json');
let registros = []; // [{ uf, nome_enc, tel_enc, criado }]

function carregar() {
  try {
    if (fs.existsSync(DB_PATH)) {
      registros = JSON.parse(fs.readFileSync(DB_PATH, 'utf8')) || [];
    }
  } catch (e) {
    console.error('Falha ao carregar dados:', e.message);
    registros = [];
  }
}

let salvando = false, pendente = false;
function salvar() {
  // grava de forma assíncrona e segura (escreve em temp e renomeia)
  if (salvando) { pendente = true; return; }
  salvando = true;
  const tmp = DB_PATH + '.tmp';
  fs.writeFile(tmp, JSON.stringify(registros), (err) => {
    if (!err) { try { fs.renameSync(tmp, DB_PATH); } catch (e) {} }
    salvando = false;
    if (pendente) { pendente = false; salvar(); }
  });
}

carregar();

const UFS = new Set(['AC','AL','AP','AM','BA','CE','DF','ES','GO','MA','MT','MS','MG','PA','PB','PR','PE','PI','RJ','RN','RS','RO','RR','SC','SP','SE','TO']);

// ──────────────────────────────────────────────────────────
//  3) APP + HEADERS DE SEGURANÇA
// ──────────────────────────────────────────────────────────
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

// ──────────────────────────────────────────────────────────
//  4) RATE LIMITING + HELPERS
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

function placarAtual() {
  const porEstado = {};
  for (const r of registros) porEstado[r.uf] = (porEstado[r.uf] || 0) + 1;
  return { total: registros.length, porEstado };
}

// ──────────────────────────────────────────────────────────
//  5) ROTAS
// ──────────────────────────────────────────────────────────
app.get('/api/placar', (req, res) => {
  if (!limitar(ipDe(req), 120, 60000)) {
    return res.status(429).json({ erro: 'Muitas requisições. Aguarde.' });
  }
  res.json(placarAtual());
});

app.post('/api/registrar', (req, res) => {
  if (!limitar(ipDe(req), 15, 60000)) {
    return res.status(429).json({ erro: 'Muitos registros em pouco tempo. Aguarde um instante.' });
  }

  const uf = limpar(req.body?.uf, 2).toUpperCase();
  const nome = limpar(req.body?.nome, 120);
  const tel = limpar(req.body?.tel, 20);

  if (!UFS.has(uf)) return res.status(400).json({ erro: 'Estado inválido.' });
  if (nome.length < 3) return res.status(400).json({ erro: 'Nome muito curto.' });

  registros.push({
    uf,
    nome_enc: encrypt(nome),
    tel_enc: tel ? encrypt(tel) : null,
    criado: new Date().toISOString()
  });
  salvar();

  res.json({ ok: true, ...placarAtual() });
});

// Exportação administrativa (descriptografada) — protegida por ADMIN_TOKEN
app.get('/api/export', (req, res) => {
  const token = process.env.ADMIN_TOKEN;
  if (!token || req.query.chave !== token) {
    return res.status(403).json({ erro: 'Acesso negado.' });
  }
  const dados = registros.map((r, i) => ({
    id: i + 1,
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
