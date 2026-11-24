require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

// 1. الأمان وضبط الترويسات والسماح باتصال تطبيق الهاتف (Security Headers & CORS)
app.use(helmet({
  crossOriginResourcePolicy: false,
  crossOriginOpenerPolicy: false
}));

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && origin !== 'null') {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  } else {
    res.header('Access-Control-Allow-Origin', '*');
  }
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// طباعة الطلبات الواردة في سجلات Render لتسهيل المتابعة
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

// رفع حد استقبال البيانات لدعم صور الفواتير والمركبات المرفقة بدقة عالية
const bodyLimit = process.env.BODY_LIMIT || '25mb';
app.use(express.json({ limit: bodyLimit }));
app.use(express.urlencoded({ extended: true, limit: bodyLimit }));

const JWT_SECRET = process.env.JWT_SECRET || 'wheel_default_secret_jwt_key_2026';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';

// إعداد مجمع الاتصال بقاعدة بيانات PostgreSQL (Connection Pool)
// تفعيل SSL تلقائياً لأي قاعدة بيانات سحابية غير محلية لضمان العمل مع Supabase
const dbUrl = process.env.DATABASE_URL || '';
const isLocalhost = dbUrl.includes('localhost') || dbUrl.includes('127.0.0.1');
const pool = new Pool({
  connectionString: dbUrl,
  ssl: !isLocalhost ? { rejectUnauthorized: false } : false
});

// منع توقف السيرفر عند انقطاع مفاجئ في اتصال قاعدة البيانات الخامل
pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL pool error:', err.message);
});

// وسيط التحقق الأمني من الرمز المميز (JWT Authentication Middleware)
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'غير مصرح بالدخول (رمز الدخول مفقود)' });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) {
      return res.status(403).json({ error: 'انتهت صلاحية الجلسة أو الرمز غير صالح، يرجى تسجيل الدخول مجدداً' });
    }
    req.user = decodedUser;
    next();
  });
}

// دالة مساعدة لتجزئة كلمات المرور والتحقق منها (SHA-256)
function hashPassword(pass) {
  return crypto.createHash('sha256').update(String(pass)).digest('hex');
}

// دالة توثيق العمليات في سجل التدقيق الأمني (Audit Logging)
async function logAudit(action, entityType, entityId, actorId, actorName, details) {
  try {
    await pool.query(
      `INSERT INTO audit_logs (action, entity_type, entity_id, actor_id, actor_name, details, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
      [action, entityType, entityId, actorId, actorName, JSON.stringify(details || {})]
    );
  } catch (e) {
    console.warn('Audit Log Warning:', e.message);
  }
}

// ==============================================================================
// 0. المسار الرئيسي لفحص جاهزية السيرفر من المتصفح والتطبيق
// ==============================================================================
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'online',
    system: 'Wheel Maintenance Cloud API',
    message: 'Server is running'
  });
});

// ==============================================================================
// 1. فحص صحة وحالة السيرفر (Health Check & Info)
// ==============================================================================
app.get('/api/health', async (req, res) => {
  let dbStatus = 'disconnected';
  try {
    await pool.query('SELECT NOW() as db_time');
    dbStatus = 'connected';
  } catch (e) {
 
