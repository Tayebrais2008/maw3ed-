const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const { Pool } = require('pg');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
if (!process.env.DATABASE_URL) throw new Error('أضف DATABASE_URL لقاعدة PostgreSQL قبل تشغيل الخادم.');
const scriptText = fs.readFileSync(path.join(ROOT, 'script.js'), 'utf8');
const match = scriptText.match(/const DOCTORS = (\[[\s\S]*?\]);/);
if (!match) throw new Error('تعذر قراءة قائمة الأطباء من script.js');
const DOCTORS = vm.runInNewContext(match[1]);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined });
const setupKey = process.env.ADMIN_SETUP_KEY || crypto.randomBytes(32).toString('base64url');
const authSecret = process.env.AUTH_SECRET || crypto.randomBytes(48).toString('base64url');
if (!process.env.ADMIN_SETUP_KEY) console.warn(`مفتاح إعداد المسؤول لهذه الجلسة فقط: ${setupKey}`);
if (!process.env.AUTH_SECRET) console.warn('عيّن AUTH_SECRET ثابتًا قبل النشر العام حتى تبقى الجلسات صالحة بعد إعادة التشغيل.');
const loginAttempts = new Map();
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

function send(res, status, value, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
  res.end(type.startsWith('application/json') ? JSON.stringify(value) : value);
}
function body(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 10000) reject(new Error('حجم الطلب كبير'));
    });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { reject(new Error('بيانات غير صالحة')); } });
    req.on('error', reject);
  });
}
function sameSecret(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function hashPassword(password, salt) { return crypto.scryptSync(password, salt, 64).toString('hex'); }
function randomPassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
  return Array.from(crypto.randomBytes(20), byte => alphabet[byte % alphabet.length]).join('');
}
function signSession(doctorId) {
  const payload = Buffer.from(JSON.stringify({ doctorId, exp: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', authSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}
function readSession(req) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', authSecret).update(payload).digest('base64url');
  if (!sameSecret(signature, expected)) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return session.exp > Date.now() ? session : null;
  } catch { return null; }
}
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS doctors (
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, specialty TEXT NOT NULL,
      clinic TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '',
      hours TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS doctor_accounts (
      doctor_id INTEGER PRIMARY KEY REFERENCES doctors(id) ON DELETE CASCADE,
      salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS requests (
      id UUID PRIMARY KEY, doctor_id INTEGER NOT NULL REFERENCES doctors(id),
      patient TEXT NOT NULL, condition TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), status TEXT NOT NULL DEFAULT 'pending', visit_time TEXT
    );
    CREATE INDEX IF NOT EXISTS requests_doctor_created_idx ON requests (doctor_id, created_at DESC);
  `);
  for (const doctor of DOCTORS) {
    await pool.query(`INSERT INTO doctors(id,name,specialty,clinic,address,hours,phone)
      VALUES($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,specialty=EXCLUDED.specialty,clinic=EXCLUDED.clinic,address=EXCLUDED.address,hours=EXCLUDED.hours,phone=EXCLUDED.phone`,
      [doctor.id, doctor.name, doctor.specialty, doctor.clinic || '', doctor.address || '', doctor.hours || '', doctor.phone || '']);
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (req.method === 'GET' && url.pathname === '/api/admin/status') {
      const result = await pool.query('SELECT COUNT(*)::int AS count FROM doctor_accounts');
      return send(res, 200, { initialized: result.rows[0].count === DOCTORS.length });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/bootstrap') {
      if (!sameSecret(req.headers['x-admin-setup-key'], setupKey)) return send(res, 403, { error: 'مفتاح إعداد المسؤول غير صحيح.' });
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const current = await client.query('SELECT COUNT(*)::int AS count FROM doctor_accounts');
        if (current.rows[0].count !== 0) {
          await client.query('ROLLBACK');
          return send(res, 409, { error: 'تم إنشاء كلمات المرور من قبل. لا يمكن عرضها مرة أخرى.' });
        }
        const credentials = [];
        for (const doctor of DOCTORS) {
          const password = randomPassword();
          const salt = crypto.randomBytes(16).toString('hex');
          await client.query('INSERT INTO doctor_accounts(doctor_id,salt,password_hash) VALUES($1,$2,$3)', [doctor.id, salt, hashPassword(password, salt)]);
          credentials.push({ doctor: doctor.name, specialty: doctor.specialty, password });
        }
        await client.query('COMMIT');
        return send(res, 200, { credentials });
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally { client.release(); }
    }
    if (req.method === 'POST' && url.pathname === '/api/doctor/login') {
      const data = await body(req);
      const doctorId = Number(data.doctorId);
      const ip = req.socket.remoteAddress || 'unknown';
      const key = `${ip}:${doctorId}`;
      const recent = (loginAttempts.get(key) || []).filter(time => Date.now() - time < 10 * 60 * 1000);
      if (recent.length >= 8) return send(res, 429, { error: 'محاولات كثيرة. انتظر قليلًا ثم حاول مجددًا.' });
      recent.push(Date.now());
      loginAttempts.set(key, recent);
      const result = await pool.query('SELECT salt,password_hash FROM doctor_accounts WHERE doctor_id=$1', [doctorId]);
      const account = result.rows[0];
      const candidate = hashPassword(String(data.password || ''), account?.salt || 'invalid-doctor-salt');
      if (!account || !sameSecret(candidate, account.password_hash)) return send(res, 401, { error: 'كلمة المرور غير صحيحة. تحقق من اسم الطبيب وكلمة المرور.' });
      loginAttempts.delete(key);
      return send(res, 200, { token: signSession(doctorId), doctorId });
    }
    if (req.method === 'POST' && url.pathname === '/api/requests') {
      const data = await body(req);
      const doctorId = Number(data.doctorId);
      const patient = String(data.patient || '').trim();
      const condition = String(data.condition || '').trim();
      if (!DOCTORS.some(item => item.id === doctorId) || patient.length < 3 || patient.length > 100 || !condition || condition.length > 120) {
        return send(res, 400, { error: 'بيانات الطلب غير مكتملة.' });
      }
      const id = crypto.randomUUID();
      await pool.query('INSERT INTO requests(id,doctor_id,patient,condition) VALUES($1,$2,$3,$4)', [id, doctorId, patient, condition]);
      return send(res, 201, { id });
    }
    if (req.method === 'GET' && url.pathname === '/api/doctor/requests') {
      const session = readSession(req);
      if (!session) return send(res, 401, { error: 'انتهت الجلسة. سجّل الدخول مرة أخرى.' });
      const result = await pool.query('SELECT id,patient,condition,created_at AS "createdAt",status,visit_time AS "visitTime" FROM requests WHERE doctor_id=$1 ORDER BY created_at DESC', [session.doctorId]);
      return send(res, 200, result.rows);
    }
    if (req.method === 'GET' && url.pathname.startsWith('/api/')) return send(res, 404, { error: 'المسار غير موجود.' });
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'الطريقة غير مدعومة.' });
    const requested = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
    const file = path.resolve(ROOT, `.${requested}`);
    if (!file.startsWith(`${ROOT}${path.sep}`)) return send(res, 404, { error: 'الملف غير موجود.' });
    if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
    res.writeHead(200, { 'Content-Type': mime[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  } catch (error) {
    console.error(error);
    if (!res.headersSent) send(res, 500, { error: 'حدث خطأ في الخادم. حاول لاحقًا.' });
    else res.end();
  }
});

initializeDatabase().then(() => server.listen(PORT, '0.0.0.0', () => console.log(`موعد يعمل على المنفذ ${PORT}`))).catch(error => {
  console.error('فشل إعداد قاعدة البيانات:', error);
  process.exit(1);
});
