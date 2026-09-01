require('dotenv').config();
const express = require('express');
console.log('RESEND KEY:', process.env.RESEND_API_KEY ? 'موجود' : 'غير موجود');
console.log('FROM EMAIL:', process.env.FROM_EMAIL || 'غير موجود');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const { Resend } = require('resend');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use(express.static(__dirname));

const PORT = process.env.PORT || 8080;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = process.env.DB_FILE || path.join(DATA_DIR, 'members.sqlite');
fs.mkdirSync(DATA_DIR, { recursive: true });

const members = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'members.json'), 'utf8'));
const memberByName = new Map();
for (const m of members) {
  const key = normalizeName(m.name);
  if (!memberByName.has(key)) memberByName.set(key, []);
  memberByName.get(key).push(m);
}

const db = new Database(DB_FILE);
// إضافة البريد الإلكتروني إلى جدول الطلبات إذا لم يكن موجودًا
try {
  const requestColumns = db.prepare(`
    PRAGMA table_info(member_requests)
  `).all();

  const hasEmail = requestColumns.some(col => col.name === 'email');

  if (!hasEmail) {
    db.exec(`
      ALTER TABLE member_requests
      ADD COLUMN email TEXT NOT NULL DEFAULT ''
    `);
  }
} catch (e) {
  console.error('[DB MIGRATION] member_requests:', e.message);
}
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS registrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  registration_token_hash TEXT NOT NULL UNIQUE,
  member_number INTEGER NOT NULL,
  name TEXT NOT NULL,
  area TEXT NOT NULL,
  phone TEXT NOT NULL,
  national_id TEXT NOT NULL,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  code_expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_sent_at INTEGER NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS member_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_number INTEGER NOT NULL UNIQUE,
  name TEXT NOT NULL,
  area TEXT NOT NULL,
  national_id TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  verified_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS member_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS member_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER NOT NULL,
  member_number INTEGER NOT NULL,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  area TEXT NOT NULL,
  national_id TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'جديد',
  admin_note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_member_requests_created_at ON member_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_member_requests_member_number ON member_requests(member_number);
`);

// Safe migration for databases created by the previous version.
const registrationColumns = db.prepare("PRAGMA table_info(registrations)").all();
if (!registrationColumns.some(c => c.name === 'national_id')) {
  db.exec("ALTER TABLE registrations ADD COLUMN national_id TEXT NOT NULL DEFAULT ''");
}
const memberProfileColumns = db.prepare("PRAGMA table_info(member_profiles)").all();
if (!memberProfileColumns.some(c => c.name === 'password_hash')) {
  db.exec("ALTER TABLE member_profiles ADD COLUMN password_hash TEXT");
}
db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS idx_reg_email_verified ON registrations(email) WHERE verified=1;
  CREATE UNIQUE INDEX IF NOT EXISTS idx_reg_national_verified ON registrations(national_id) WHERE verified=1 AND national_id <> '';
`);

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
console.log('RESEND CHECK:', {
  hasKey: !!process.env.RESEND_API_KEY,
  fromEmail: process.env.FROM_EMAIL || '(empty)'
});
const FROM_EMAIL = process.env.FROM_EMAIL || '';
const APP_NAME = 'بوابة أعضاء الجمعية';

function normalizeName(value) {
  return String(value || '')
    .trim()
    .replace(/[إأآٱ]/g, 'ا')
    .replace(/ى/g, 'ي')
    .replace(/ة/g, 'ه')
    .replace(/\s+/g, ' ')
    .toLowerCase();
}
function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}
function makeCode() {
  return String(crypto.randomInt(100000, 1000000));
}
function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}
function verifyPassword(password, stored) {
  try {
    const parts = String(stored || '').split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const derived = crypto.scryptSync(password, parts[1], 64);
    const expected = Buffer.from(parts[2], 'hex');
    return expected.length === derived.length && crypto.timingSafeEqual(derived, expected);
  } catch (_) {
    return false;
  }
}
function validPassword(v) {
  const p = String(v || '');
  return p.length >= 8 && p.length <= 128;
}
function normalizePhone(v) {
  return normalizeDigits(String(v || '')).replace(/[\s\-]/g, '');
}
function findMemberByIdentifier(identifier) {
  const value = String(identifier || '').trim();
  if (validEmail(value.toLowerCase())) {
    return db.prepare('SELECT * FROM member_profiles WHERE lower(email)=lower(?)').get(value);
  }
  const phone = normalizePhone(value);
  return db.prepare('SELECT * FROM member_profiles WHERE replace(replace(phone, " ", ""), "-", "")=?').get(phone);
}
function publicBaseUrl(req) {
  return String(process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
}
function validEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}
function validPhone(v) {
  return /^[0-9٠-٩+\-\s]{8,20}$/.test(v);
}
function normalizeDigits(value) {
  return String(value || '').replace(/[٠-٩]/g, d => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)));
}
function validNationalId(v) {
  return /^\d{14}$/.test(normalizeDigits(v));
}
function validArabicQuadName(v) {
  const clean = String(v || '').trim().replace(/\s+/g, ' ');
  const words = clean.split(' ');
  return words.length === 4 && words.every(w => /^[\u0600-\u06FF]+$/.test(w));
}
function findMemberByName(name) {
  const matches = memberByName.get(normalizeName(name)) || [];
  return matches;
}
async function sendCode(email, code, name) {
  console.log('[SENDCODE CHECK]', {
    resendExists: !!resend,
    fromEmailExists: !!FROM_EMAIL,
    fromEmail: FROM_EMAIL || '(empty)'
  });

  if (!resend || !FROM_EMAIL) {
    if (process.env.DEV_LOG_CODE === 'true') {
      console.log(`[DEV] Verification code for ${email}: ${code}`);
      return;
    }
    throw new Error('خدمة البريد غير مهيأة بعد. أضف RESEND_API_KEY وFROM_EMAIL في ملف .env');
  }
  const { error } = await resend.emails.send({
  from: FROM_EMAIL,
  to: [email],
  subject: 'كود تفعيل حساب العضو',
  html: `
    <div dir="rtl" style="font-family:Arial,sans-serif;line-height:1.8">
      <h2>${APP_NAME}</h2>
      <p>مرحبًا ${escapeHtml(name)}،</p>
      <p>كود تفعيل حسابك هو:</p>
      <div style="font-size:34px;font-weight:700;letter-spacing:8px">${code}</div>
      <p>الكود صالح لمدة 10 دقائق.</p>
      <p style="color:#777">إذا لم تطلب هذا التسجيل، يمكنك تجاهل الرسالة.</p>
    </div>`
});

if (error) {
  console.error('[RESEND ERROR]', error);
  throw new Error('تعذر إرسال كود التفعيل حاليًا. راجع شاشة السيرفر لمعرفة السبب.');
}
}

async function sendResetEmail(email, name, resetUrl) {
  if (!resend || !FROM_EMAIL) {
    if (process.env.DEV_LOG_CODE === 'true') {
      console.log(`[DEV] Password reset link for ${email}: ${resetUrl}`);
      return;
    }
    throw new Error('خدمة البريد غير مهيأة بعد. أضف RESEND_API_KEY وFROM_EMAIL في ملف .env');
  }
  const { error } = await resend.emails.send({
    from: FROM_EMAIL,
    to: [email],
    subject: 'إعادة تعيين كلمة المرور — بوابة أعضاء الجمعية',
    html: `
      <div dir="rtl" style="font-family:Arial,sans-serif;line-height:1.9;background:#f7f5ef;padding:28px">
        <div style="max-width:620px;margin:auto;background:#ffffff;border:1px solid #e7e2d6;border-radius:16px;padding:32px">
          <h2 style="color:#122a3a;margin-top:0">بوابة أعضاء الجمعية</h2>
          <p>مرحبًا ${escapeHtml(name)}،</p>
          <p>تلقينا طلبًا لإعادة تعيين كلمة المرور الخاصة بحسابك.</p>
          <p>اضغط على الزر التالي للانتقال إلى الموقع وتعيين كلمة المرور الجديدة. ستحتاج إلى إدخال بريدك الإلكتروني وكلمة المرور الجديدة مرتين للتأكيد.</p>
          <p style="text-align:center;margin:28px 0">
            <a href="${escapeHtml(resetUrl)}" style="display:inline-block;background:#d9a441;color:#122a3a;text-decoration:none;font-weight:700;padding:13px 28px;border-radius:9px">إعادة تعيين كلمة المرور</a>
          </p>
          <p style="font-size:13px;color:#777">صلاحية الرابط 30 دقيقة. إذا لم تطلب إعادة تعيين كلمة المرور، يمكنك تجاهل هذه الرسالة.</p>
        </div>
      </div>`
  });
if (error) {
  console.error('[RESEND ERROR]', error);
  throw new Error('تعذر إرسال كود التفعيل حاليًا. راجع شاشة السيرفر.');
}}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
}

// Basic per-IP request throttling.
const ipHits = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const hit = ipHits.get(ip) || { count: 0, reset: now + 15*60*1000 };
  if (now > hit.reset) { hit.count = 0; hit.reset = now + 15*60*1000; }
  hit.count++;
  ipHits.set(ip, hit);
  if (hit.count > 30) return res.status(429).json({message:'تم تجاوز عدد المحاولات. حاول لاحقًا.'});
  next();
}

app.post('/api/register/request-code', rateLimit, async (req,res) => {
  const name = String(req.body.name || '').trim();
  const area = String(req.body.area || '').trim();
  const nationalId = normalizeDigits(req.body.nationalId || '').trim();
  const phone = String(req.body.phone || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();

  if (!validArabicQuadName(name)) return res.status(400).json({message:'اكتب الاسم رباعي باللغة العربية، 4 أسماء، كما هو مسجل بالكشف.'});
  if (!area || area.length > 120) return res.status(400).json({message:'اكتب الإدارة أو المنطقة.'});
  if (!validNationalId(nationalId)) return res.status(400).json({message:'اكتب الرقم القومي صحيحًا، ويجب أن يتكون من 14 رقمًا.'});
  if (!validPhone(phone)) return res.status(400).json({message:'اكتب رقم موبايل صحيح.'});
  if (!validEmail(email)) return res.status(400).json({message:'اكتب بريدًا إلكترونيًا صحيحًا.'});

  const matches = findMemberByName(name);
  if (!matches.length) return res.status(404).json({message:'الاسم غير موجود ضمن كشف العضوية السارية. تأكد من كتابة الاسم كما هو بالكشف.'});
  if (matches.length > 1) return res.status(409).json({message:'يوجد أكثر من عضو بنفس الاسم. لا يمكن إكمال التسجيل بالاسم فقط؛ سيتم حل هذه الحالة عند إضافة الرقم القومي.'});

  const existingEmail = db.prepare('SELECT id FROM member_profiles WHERE email=?').get(email);
  if (existingEmail) return res.status(409).json({message:'هذا البريد الإلكتروني مسجل بالفعل.'});
  const existingNational = db.prepare('SELECT id FROM member_profiles WHERE national_id=?').get(nationalId);
  if (existingNational) return res.status(409).json({message:'هذا الرقم القومي مسجل بالفعل.'});
  const existingMember = db.prepare('SELECT id FROM member_profiles WHERE member_number=?').get(matches[0].memberNumber);
  if (existingMember) return res.status(409).json({message:'هذا العضو لديه حساب مسجل بالفعل.'});

  const now = Date.now();
  const code = makeCode();
  const token = makeToken();
  const tokenHash = hash(token);

  try {
    await sendCode(email, code, name);
  } catch (e) {
    return res.status(503).json({message:e.message});
  }

  db.prepare(`
    INSERT INTO registrations
      (registration_token_hash,member_number,name,area,phone,national_id,email,code_hash,code_expires_at,attempts,last_sent_at,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(registration_token_hash) DO UPDATE SET
      code_hash=excluded.code_hash, code_expires_at=excluded.code_expires_at,
      attempts=0, last_sent_at=excluded.last_sent_at
  `).run(tokenHash, matches[0].memberNumber, matches[0].name, area, phone, nationalId, email, hash(code), now+10*60*1000, 0, now, now);

  return res.json({registrationToken: token, message:'تم إرسال كود التفعيل إلى بريدك الإلكتروني.'});
});

app.post('/api/register/resend-code', rateLimit, async (req,res) => {
  const token = String(req.body.registrationToken || '');
  const row = db.prepare('SELECT * FROM registrations WHERE registration_token_hash=?').get(hash(token));
  if (!row || row.verified) return res.status(400).json({message:'جلسة التسجيل غير صالحة. ابدأ التسجيل من جديد.'});
  if (Date.now() - row.last_sent_at < 60*1000) return res.status(429).json({message:'انتظر دقيقة قبل إعادة إرسال الكود.'});

  const code = makeCode();
  try { await sendCode(row.email, code, row.name); }
  catch(e){ return res.status(503).json({message:e.message}); }

  db.prepare('UPDATE registrations SET code_hash=?, code_expires_at=?, attempts=0, last_sent_at=? WHERE id=?')
    .run(hash(code), Date.now()+10*60*1000, Date.now(), row.id);

  res.json({message:'تم إرسال كود جديد إلى بريدك الإلكتروني.'});
});

app.post('/api/register/verify-code', rateLimit, (req,res) => {
  const token = String(req.body.registrationToken || '');
  const code = String(req.body.code || '').trim();
  const row = db.prepare('SELECT * FROM registrations WHERE registration_token_hash=?').get(hash(token));
  if (!row || row.verified) return res.status(400).json({message:'جلسة التسجيل غير صالحة.'});
  if (Date.now() > row.code_expires_at) return res.status(400).json({message:'انتهت صلاحية الكود. اطلب كودًا جديدًا.'});
  if (row.attempts >= 5) return res.status(429).json({message:'تم تجاوز عدد محاولات إدخال الكود. اطلب كودًا جديدًا.'});

  if (hash(code) !== row.code_hash) {
    db.prepare('UPDATE registrations SET attempts=attempts+1 WHERE id=?').run(row.id);
    return res.status(400).json({message:'كود التفعيل غير صحيح.'});
  }

  const verifyNow = Date.now();
  try {
    db.prepare(`INSERT INTO member_profiles
      (member_number,name,area,national_id,phone,email,verified_at,created_at)
      VALUES (?,?,?,?,?,?,?,?)`).run(
      row.member_number, row.name, row.area, row.national_id, row.phone, row.email, verifyNow, row.created_at
    );
    db.prepare('UPDATE registrations SET verified=1 WHERE id=?').run(row.id);
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({message:'بيانات العضو مسجلة بالفعل أو تم استخدامها من قبل.'});
    return res.status(500).json({message:'تعذر حفظ بيانات التسجيل. حاول مرة أخرى.'});
  }
  res.json({memberNumber: row.member_number, name: row.name});
});


function getAuthenticatedMember(req) {
  const token = String(req.headers['x-session-token'] || req.body?.sessionToken || '').trim();
  if (!token) return null;
  const row = db.prepare(`
    SELECT ms.*, mp.member_number, mp.name, mp.area, mp.national_id, mp.phone, mp.email
    FROM member_sessions ms
    JOIN member_profiles mp ON mp.id=ms.member_id
    WHERE ms.token_hash=? AND ms.expires_at>?
  `).get(hash(token), Date.now());
  return row || null;
}

app.get('/api/member/me', (req,res) => {
  const member = getAuthenticatedMember(req);
  if (!member) return res.status(401).json({message:'برجاء تسجيل الدخول أولًا.'});
  res.json({member:{
    name:member.name,
    nationalId:member.national_id,
    phone:member.phone,
    memberNumber:member.member_number,
    area:member.area,
    email:member.email
  }});
});

app.post('/api/member/requests', rateLimit, (req,res) => {

  const member = getAuthenticatedMember(req);

  const message = String(req.body.message || '').trim();

  if (!message) {
    return res.status(400).json({
      message:'اكتب الرسالة أو الطلب قبل الإرسال.'
    });
  }

  if (message.length > 10000) {
    return res.status(400).json({
      message:'الرسالة طويلة جدًا. الحد الأقصى 10000 حرف.'
    });
  }

  let memberId = 0;
  let memberNumber = 0;
  let name = '';
  let phone = '';
  let area = '';
  let nationalId = '';
  let email = '';

  if (member) {

    // عضو مسجل: نأخذ البيانات من حسابه
    memberId = member.member_id;
    memberNumber = member.memberNumber || member.member_number || 0;
    name = member.name;
    phone = member.phone;
    area = member.area;
    nationalId = member.nationalId || member.national_id;
    email = member.email || '';

  } else {

    // زائر غير مسجل: نأخذ البيانات من النموذج
    name = String(req.body.name || '').trim();
    phone = String(req.body.phone || '').trim();
    area = String(req.body.area || '').trim();
    nationalId = String(req.body.nationalId || '').trim();
    email = String(req.body.email || '').trim();

    if (!name) {
      return res.status(400).json({message:'اكتب اسم العضو.'});
    }

    if (!phone) {
      return res.status(400).json({message:'اكتب رقم الموبايل.'});
    }

    if (!area) {
      return res.status(400).json({message:'اكتب الإدارة أو المنطقة.'});
    }

    if (!nationalId) {
      return res.status(400).json({message:'اكتب الرقم القومي.'});
    }

    if (!email) {
      return res.status(400).json({message:'اكتب البريد الإلكتروني.'});
    }

    if (!/^\d{14}$/.test(nationalId)) {
      return res.status(400).json({
        message:'الرقم القومي يجب أن يكون 14 رقمًا.'
      });
    }

  }

  const now = Date.now();

  const info = db.prepare(`
    INSERT INTO member_requests
    (member_id,member_number,name,phone,area,national_id,message,status,admin_note,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    memberId,
    memberNumber,
    name,
    phone,
    area,
    nationalId,
    message,
    'جديد',
    email,
    now,
    now
  );

  res.json({
    message:'تم إرسال طلبك/مراسلتك بنجاح، وسيتم مراجعته من إدارة الجمعية.',
    requestId:info.lastInsertRowid
  });

});

app.get('/api/admin/requests', (req,res) => {
  const key = String(req.headers['x-admin-key'] || req.query.key || '').trim();
  if (!process.env.ADMIN_KEY || key !== process.env.ADMIN_KEY) return res.status(401).json({message:'غير مصرح.'});
  const q = String(req.query.q || '').trim();
  const status = String(req.query.status || '').trim();
  let sql = 'SELECT * FROM member_requests';
  const params = [];
  const where = [];
  if (q) {
    where.push('(CAST(id AS TEXT) LIKE ? OR CAST(member_number AS TEXT) LIKE ? OR name LIKE ? OR phone LIKE ? OR national_id LIKE ? OR message LIKE ?)');
    const like = `%${q}%`; params.push(like,like,like,like,like,like);
  }
  if (status) { where.push('status=?'); params.push(status); }
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY created_at DESC';
  const rows = db.prepare(sql).all(...params).map(r => ({...r, createdAt:new Date(r.created_at).toISOString(), updatedAt:new Date(r.updated_at).toISOString()}));
  res.json({requests:rows});
});

app.patch('/api/admin/requests/:id', (req,res) => {
  const key = String(req.headers['x-admin-key'] || req.body?.adminKey || '').trim();
  if (!process.env.ADMIN_KEY || key !== process.env.ADMIN_KEY) return res.status(401).json({message:'غير مصرح.'});
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({message:'رقم الطلب غير صحيح.'});
  const status = String(req.body.status || '').trim();
  const note = String(req.body.adminNote || '').trim();
  const allowed = ['جديد','قيد المراجعة','تم الرد','مغلق'];
  if (!allowed.includes(status)) return res.status(400).json({message:'حالة الطلب غير صحيحة.'});
  const now = Date.now();
  const result = db.prepare('UPDATE member_requests SET status=?,admin_note=?,updated_at=? WHERE id=?').run(status,note,now,id);
  if (!result.changes) return res.status(404).json({message:'الطلب غير موجود.'});
  res.json({message:'تم تحديث الطلب.'});
});

app.post('/api/auth/forgot-password', rateLimit, async (req,res) => {
  const identifier = String(req.body.identifier || '').trim();
  if (!identifier) return res.status(400).json({message:'اكتب البريد الإلكتروني أو رقم الهاتف.'});

  const member = findMemberByIdentifier(identifier);
  if (!member) {
    if (validEmail(identifier)) return res.status(404).json({message:'الإيميل غير مسجل لدينا.'});
    return res.status(404).json({message:'رقم الموبايل غير مسجل لدينا.'});
  }
  const genericMessage = 'تم إرسال رابط إعادة تعيين كلمة المرور إلى البريد الإلكتروني المسجل لدينا.';

  const token = makeToken();
  const now = Date.now();
  db.prepare('DELETE FROM password_resets WHERE member_id=? OR expires_at<?').run(member.id, now);
  db.prepare('INSERT INTO password_resets (member_id,token_hash,expires_at,created_at) VALUES (?,?,?,?)')
    .run(member.id, hash(token), now + 30*60*1000, now);

  const resetUrl = `${publicBaseUrl(req)}/?resetToken=${encodeURIComponent(token)}`;
  try {
    await sendResetEmail(member.email, member.name, resetUrl);
  } catch (e) {
    db.prepare('DELETE FROM password_resets WHERE token_hash=?').run(hash(token));
    return res.status(503).json({message:e.message});
  }
  return res.json({message: genericMessage});
});

app.post('/api/auth/reset-password', rateLimit, (req,res) => {
  const token = String(req.body.token || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const confirmPassword = String(req.body.confirmPassword || '');

  if (!token) return res.status(400).json({message:'رابط إعادة التعيين غير صالح.'});
  if (!validEmail(email)) return res.status(400).json({message:'اكتب البريد الإلكتروني المسجل بالحساب.'});
  if (!validPassword(password)) return res.status(400).json({message:'كلمة المرور يجب ألا تقل عن 8 أحرف.'});
  if (password !== confirmPassword) return res.status(400).json({message:'كلمتا المرور غير متطابقتين.'});

  const row = db.prepare(`
    SELECT pr.*, mp.email, mp.name, mp.member_number
    FROM password_resets pr
    JOIN member_profiles mp ON mp.id=pr.member_id
    WHERE pr.token_hash=? AND pr.expires_at>? AND lower(mp.email)=?
  `).get(hash(token), Date.now(), email);

  if (!row) return res.status(400).json({message:'الرابط غير صالح أو انتهت صلاحيته أو البريد الإلكتروني غير مطابق.'});

  const passwordHash = hashPassword(password);
  const now = Date.now();
  db.prepare('UPDATE member_profiles SET password_hash=? WHERE id=?').run(passwordHash, row.member_id);
  db.prepare('DELETE FROM password_resets WHERE member_id=?').run(row.member_id);
  db.prepare('DELETE FROM member_sessions WHERE member_id=?').run(row.member_id);

  const sessionToken = makeToken();
  db.prepare('INSERT INTO member_sessions (member_id,token_hash,expires_at,created_at) VALUES (?,?,?,?)')
    .run(row.member_id, hash(sessionToken), now + 7*24*60*60*1000, now);

  res.json({message:'تم تغيير كلمة المرور وتسجيل دخولك بنجاح.', sessionToken, member:{memberNumber:row.member_number,name:row.name,email:row.email}});
});

app.post('/api/auth/login', rateLimit, (req,res) => {
  const identifier = String(req.body.identifier || '').trim();
  const password = String(req.body.password || '');
  if (!identifier || !password) return res.status(400).json({message:'اكتب البريد الإلكتروني أو رقم الهاتف وكلمة المرور.'});

  const member = findMemberByIdentifier(identifier);
  if (!member) {
    if (validEmail(identifier)) return res.status(401).json({message:'الإيميل غير مسجل لدينا.'});
    return res.status(401).json({message:'رقم الموبايل غير مسجل لدينا.'});
  }
  if (!member.password_hash) {
    return res.status(401).json({message:'الحساب مسجل لدينا ولكن لم يتم إنشاء كلمة مرور بعد. استخدم «نسيت كلمة المرور» لإنشاء كلمة المرور.'});
  }
  if (!verifyPassword(password, member.password_hash)) {
    return res.status(401).json({message:'بيانات الدخول غير صحيحة.'});
  }

  const token = makeToken();
  const now = Date.now();
  db.prepare('INSERT INTO member_sessions (member_id,token_hash,expires_at,created_at) VALUES (?,?,?,?)')
    .run(member.id, hash(token), now + 7*24*60*60*1000, now);

  res.json({message:'تم تسجيل الدخول بنجاح.', sessionToken:token, member:{memberNumber:member.member_number,name:member.name,email:member.email}});
});

app.post('/api/auth/logout', (req,res) => {
  const token = String(req.body.sessionToken || '').trim();
  if (token) db.prepare('DELETE FROM member_sessions WHERE token_hash=?').run(hash(token));
  res.json({message:'تم تسجيل الخروج.'});
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/{*splat}', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Member portal running on port ${PORT}`);
});