// ══════════════════════════════════════════════════════════════
//  MinhaTaxaReal — Backend
//  Stack: Node.js + Express + JWT + Kiwify Webhook + Nodemailer
//  Deploy: Render.com (free tier)
//
//  Rotas:
//    GET  /api/health              → health check
//    POST /api/auth/register       → cria usuário
//    POST /api/auth/login          → login → JWT
//    GET  /api/auth/me             → valida token
//    POST /api/auth/logout         → revoga token
//    POST /api/kiwify/webhook      → recebe eventos Kiwify
// ══════════════════════════════════════════════════════════════

require('dotenv').config();
const express    = require('express');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const cors       = require('cors');
const nodemailer = require('nodemailer');
const crypto     = require('crypto');

const app = express();

// ── CORS ──
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:5500').split(',');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.some(o => origin.startsWith(o.trim()))) return cb(null, true);
    cb(new Error('CORS bloqueado: ' + origin));
  },
  credentials: true,
}));

// Raw body para validação do webhook Kiwify (antes do express.json)
app.use('/api/kiwify/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// ══════════════════════════════════════════════════════════════
//  CONTAS ESPECIAIS — carregadas na inicialização
//  Configure no .env:
//    MASTER_EMAIL   = seu email
//    MASTER_PASS    = sua senha master (mín. 12 caracteres)
//    DEMO_PASS      = senha de demonstração
// ══════════════════════════════════════════════════════════════
async function carregarContasEspeciais() {
  // ── CONTA MASTER (proprietário) ──
  const masterEmail = process.env.MASTER_EMAIL;
  const masterPass  = process.env.MASTER_PASS;
  if (masterEmail && masterPass) {
    const hash = await bcrypt.hash(masterPass, 12);
    DB.users.set(masterEmail.toLowerCase(), {
      email: masterEmail.toLowerCase(),
      passwordHash: hash,
      name: 'Master',
      plan: 'master',
      activationPaid: true,
      isMaster: true,
      kiwifyOrderId: 'master',
      createdAt: Date.now(),
      lastLogin: null,
    });
    console.log('[MASTER] Conta master carregada:', masterEmail);
  } else {
    console.warn('[MASTER] MASTER_EMAIL ou MASTER_PASS não configurados no .env');
  }

  // ── CONTA DEMO (apresentações) ──
  const demoEmail = 'demo@minhataxareal.com.br';
  const demoPass  = process.env.DEMO_PASS;
  if (demoPass) {
    const hash = await bcrypt.hash(demoPass, 12);
    DB.users.set(demoEmail, {
      email: demoEmail,
      passwordHash: hash,
      name: 'Demonstração',
      plan: 'demo',
      activationPaid: true,
      isDemo: true,
      kiwifyOrderId: 'demo',
      createdAt: Date.now(),
      lastLogin: null,
    });
    console.log('[DEMO] Conta demo carregada:', demoEmail);
  }
}

// ══════════════════════════════════════════════════════════════
//  BANCO DE DADOS EM MEMÓRIA
//  Para produção com muitos usuários: migrar para Supabase (free)
// ══════════════════════════════════════════════════════════════
const DB = {
  users:  new Map(), // email → user
  tokens: new Map(), // jti  → { email, exp }
};

// Schema do usuário:
// { email, passwordHash, name, plan, activationPaid,
//   kiwifyOrderId, createdAt, lastLogin }

// ══════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-troque-em-producao';

function signToken(user) {
  const jti = crypto.randomBytes(16).toString('hex');
  const token = jwt.sign(
    { sub: user.email, jti, plan: user.plan, name: user.name },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  DB.tokens.set(jti, { email: user.email, exp: Date.now() + 30 * 86400 * 1000 });
  return token;
}

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    if (!DB.tokens.has(payload.jti)) {
      return res.status(401).json({ error: 'Sessão expirada' });
    }
    const user = DB.users.get(payload.sub);
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });
    if (!user.activationPaid) {
      return res.status(403).json({ error: 'Ativação pendente', code: 'ACTIVATION_REQUIRED' });
    }
    req.user = user;
    req.tokenPayload = payload;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// ── E-mail ──
const mailer = nodemailer.createTransport({
  host:   process.env.SMTP_HOST || 'smtp.gmail.com',
  port:   parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendEmail(to, subject, html) {
  if (!process.env.SMTP_USER) {
    console.log('[EMAIL SIMULADO]', { to, subject });
    return;
  }
  try {
    await mailer.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to, subject, html
    });
    console.log('[EMAIL ENVIADO]', { to, subject });
  } catch (e) {
    console.error('[EMAIL ERRO]', e.message);
  }
}

// ══════════════════════════════════════════════════════════════
//  ROTAS DE AUTENTICAÇÃO
// ══════════════════════════════════════════════════════════════

// ── Rota exclusiva master: listar usuários ──
app.get('/api/master/users', verifyToken, (req, res) => {
  if (!req.user.isMaster) {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  const lista = [...DB.users.values()].map(u => ({
    email: u.email,
    name: u.name,
    plan: u.plan,
    activationPaid: u.activationPaid,
    createdAt: new Date(u.createdAt).toISOString(),
    lastLogin: u.lastLogin ? new Date(u.lastLogin).toISOString() : null,
    isMaster: !!u.isMaster,
    isDemo: !!u.isDemo,
  }));
  res.json({ total: lista.length, users: lista });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ ok: true, ts: Date.now(), users: DB.users.size });
});

// Registro
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'E-mail, senha e nome são obrigatórios' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Senha deve ter ao menos 8 caracteres' });
  }
  const key = email.toLowerCase().trim();
  if (DB.users.has(key)) {
    return res.status(409).json({ error: 'E-mail já cadastrado' });
  }
  const passwordHash = await bcrypt.hash(password, 12);
  const user = {
    email: key, passwordHash, name,
    plan: 'none',
    activationPaid: false,
    kiwifyOrderId: null,
    createdAt: Date.now(),
    lastLogin: null,
  };
  DB.users.set(key, user);
  console.log('[REGISTRO]', key);
  res.status(201).json({ message: 'Conta criada. Faça login para continuar.' });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const key = email?.toLowerCase().trim();
  const user = DB.users.get(key);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'E-mail ou senha incorretos' });
  }
  user.lastLogin = Date.now();
  const token = signToken(user);
  console.log('[LOGIN]', key);
  res.json({
    token,
    user: {
      email: user.email,
      name: user.name,
      plan: user.plan,
      activationPaid: user.activationPaid,
    },
  });
});

// Logout
app.post('/api/auth/logout', verifyToken, (req, res) => {
  DB.tokens.delete(req.tokenPayload.jti);
  res.json({ message: 'Sessão encerrada' });
});

// Dados do usuário logado
app.get('/api/auth/me', verifyToken, (req, res) => {
  const u = req.user;
  res.json({
    email: u.email,
    name: u.name,
    plan: u.plan,
    activationPaid: u.activationPaid,
  });
});

// ══════════════════════════════════════════════════════════════
//  WEBHOOK KIWIFY
//  Kiwify envia POST para /api/kiwify/webhook com os dados
//  da venda. Validamos com o token secreto configurado no
//  painel da Kiwify em: Configurações → Webhooks
// ══════════════════════════════════════════════════════════════
app.post('/api/kiwify/webhook', async (req, res) => {

  // ── Validação da assinatura Kiwify ──
  const KIWIFY_TOKEN = process.env.KIWIFY_WEBHOOK_TOKEN;
  if (KIWIFY_TOKEN) {
    const signature = req.headers['x-kiwify-signature'] ||
                      req.headers['x-webhook-token'] || '';
    // Kiwify usa HMAC-SHA1 ou token simples dependendo da versão
    const body = req.body.toString();
    const expected = crypto
      .createHmac('sha1', KIWIFY_TOKEN)
      .update(body)
      .digest('hex');
    if (signature !== expected && signature !== KIWIFY_TOKEN) {
      console.warn('[WEBHOOK] Assinatura inválida');
      return res.status(401).json({ error: 'Assinatura inválida' });
    }
  }

  let data;
  try {
    data = JSON.parse(req.body.toString());
  } catch (e) {
    return res.status(400).json({ error: 'JSON inválido' });
  }

  console.log('[WEBHOOK KIWIFY] evento:', data.order_status, '| produto:', data.product_id);

  // ── Eventos que ativam ou bloqueiam acesso ──
  const status = data.order_status; // 'paid', 'refunded', 'chargeback', 'waiting_payment'
  const buyerEmail = data.Customer?.email?.toLowerCase().trim();
  const buyerName  = data.Customer?.full_name || data.Customer?.name || 'Cliente';
  const orderId    = data.order_id;
  const productId  = data.product_id;

  if (!buyerEmail) {
    console.warn('[WEBHOOK] E-mail do comprador não encontrado');
    return res.json({ received: true });
  }

  // ── PAGAMENTO CONFIRMADO ──
  if (status === 'paid' || status === 'complete') {

    let user = DB.users.get(buyerEmail);

    // Se o usuário ainda não criou conta, cria automaticamente
    // com senha temporária (ele vai redefinir no primeiro acesso)
    if (!user) {
      const tempPassword = crypto.randomBytes(8).toString('hex');
      const passwordHash = await bcrypt.hash(tempPassword, 12);
      user = {
        email: buyerEmail,
        passwordHash,
        name: buyerName,
        plan: 'none',
        activationPaid: false,
        kiwifyOrderId: null,
        createdAt: Date.now(),
        lastLogin: null,
        tempPassword, // guardamos para enviar no e-mail
      };
      DB.users.set(buyerEmail, user);
      console.log('[WEBHOOK] Usuário criado automaticamente:', buyerEmail);
    }

    // Ativa o acesso
    user.activationPaid = true;
    user.plan = 'active';
    user.kiwifyOrderId = orderId;

    // E-mail de boas-vindas com acesso
    const APP_URL = process.env.APP_URL || 'https://minhataxareal.com.br';
    const hasExistingAccount = !user.tempPassword;

    const emailHtml = hasExistingAccount
      ? `
        <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px;background:#0e0f11;color:#f0ede8;border-radius:12px">
          <h1 style="color:#d4f03c;font-size:24px;margin-bottom:8px">✓ Acesso liberado!</h1>
          <p style="color:#8a8880;margin-bottom:24px">Olá, <strong style="color:#f0ede8">${buyerName}</strong>! Seu pagamento foi confirmado.</p>
          <p style="color:#8a8880;margin-bottom:20px">Acesse o MinhaTaxaReal com seu e-mail e senha cadastrados:</p>
          <a href="${APP_URL}/auth.html" style="display:inline-block;background:#d4f03c;color:#0e0f11;font-weight:bold;padding:14px 28px;border-radius:8px;text-decoration:none;font-size:15px">Acessar agora →</a>
          <hr style="border:1px solid #1e2026;margin:28px 0">
          <p style="color:#545250;font-size:12px">Dúvidas? Responda este e-mail. Ferramenta de uso exclusivamente educativo e informativo.</p>
        </div>`
      : `
        <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px;background:#0e0f11;color:#f0ede8;border-radius:12px">
          <h1 style="color:#d4f03c;font-size:24px;margin-bottom:8px">✓ Acesso liberado!</h1>
          <p style="color:#8a8880;margin-bottom:24px">Olá, <strong style="color:#f0ede8">${buyerName}</strong>! Seu pagamento foi confirmado.</p>
          <p style="color:#8a8880;margin-bottom:8px">Seus dados de acesso:</p>
          <div style="background:#1e2026;border-radius:8px;padding:16px;margin-bottom:20px">
            <p style="margin:0 0 6px;color:#8a8880;font-size:13px">E-mail: <strong style="color:#f0ede8">${buyerEmail}</strong></p>
            <p style="margin:0;color:#8a8880;font-size:13px">Senha provisória: <strong style="color:#d4f03c;font-family:monospace">${user.tempPassword}</strong></p>
          </div>
          <p style="color:#8a8880;font-size:13px;margin-bottom:20px">⚠ Recomendamos que troque a senha após o primeiro acesso.</p>
          <a href="${APP_URL}/auth.html" style="display:inline-block;background:#d4f03c;color:#0e0f11;font-weight:bold;padding:14px 28px;border-radius:8px;text-decoration:none;font-size:15px">Acessar agora →</a>
          <hr style="border:1px solid #1e2026;margin:28px 0">
          <p style="color:#545250;font-size:12px">Dúvidas? Responda este e-mail. Ferramenta de uso exclusivamente educativo e informativo.</p>
        </div>`;

    // Remove a senha temporária do objeto para não ficar exposta
    delete user.tempPassword;

    await sendEmail(
      buyerEmail,
      '✓ MinhaTaxaReal — Seu acesso está pronto',
      emailHtml
    );

    console.log('[WEBHOOK] Acesso ativado e e-mail enviado para:', buyerEmail);
  }

  // ── REEMBOLSO / CHARGEBACK ── bloqueia o acesso
  if (status === 'refunded' || status === 'chargedback' || status === 'chargeback') {
    const user = DB.users.get(buyerEmail);
    if (user) {
      user.activationPaid = false;
      user.plan = 'none';
      // Revoga todos os tokens do usuário
      for (const [jti, entry] of DB.tokens.entries()) {
        if (entry.email === buyerEmail) DB.tokens.delete(jti);
      }
      console.log('[WEBHOOK] Acesso revogado por reembolso:', buyerEmail);
    }
  }

  res.json({ received: true });
});

// ══════════════════════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3001;
app.listen(PORT, async () => {
  console.log(`MinhaTaxaReal backend rodando na porta ${PORT}`);
  console.log('Ambiente:', process.env.NODE_ENV || 'development');
  // Carrega contas especiais ao iniciar
  await carregarContasEspeciais();
});

module.exports = app;
