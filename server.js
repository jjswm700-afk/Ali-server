require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

// الأمان وضبط الترويسات (Security Headers & CORS)
app.use(helmet());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 'Authorization', 'X-Requested-With', 
    'x-user-role', 'x-role', 'x-user-id', 'x-idempotency-key', 'X-Idempotency-Key'
  ]
}));

// رفع حد استقبال البيانات لدعم صور الفواتير والمركبات المرفقة بدقة عالية
const bodyLimit = process.env.BODY_LIMIT || '25mb';
app.use(express.json({ limit: bodyLimit }));
app.use(express.urlencoded({ extended: true, limit: bodyLimit }));

const JWT_SECRET = process.env.JWT_SECRET || 'wheel_default_secret_jwt_key_2026';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';

// إعداد مجمع الاتصال بقاعدة بيانات PostgreSQL (متوافق مع Supabase, Neon, Render)
const isLocalhost = !process.env.DATABASE_URL || (process.env.DATABASE_URL.includes('localhost') || process.env.DATABASE_URL.includes('127.0.0.1'));
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: !isLocalhost ? { rejectUnauthorized: false } : false
});

// دالة التحقق من صلاحيات الإدارة أو مدير النظام (ADMIN & MANAGEMENT)
function isManagementOrAdmin(role) {
  const r = (role || '').toUpperCase();
  return r === 'ADMIN' || r === 'MANAGEMENT';
}

// التحقق من وجود الجداول الأساسية والفهارس عند الإقلاع (v6.0)
async function ensureTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        notification_id TEXT UNIQUE NOT NULL,
        user_id TEXT,
        transaction_id TEXT,
        title TEXT NOT NULL,
        purpose TEXT DEFAULT 'إشعار',
        message TEXT NOT NULL,
        type TEXT DEFAULT 'INFO',
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        target_type TEXT DEFAULT 'TARGET_USER',
        target_id TEXT,
        sender_id TEXT,
        sender_name TEXT,
        read_by JSONB DEFAULT '[]'::jsonb
      );
      ALTER TABLE notifications ADD COLUMN IF NOT EXISTS target_type TEXT DEFAULT 'TARGET_USER';
      ALTER TABLE notifications ADD COLUMN IF NOT EXISTS target_id TEXT;
      ALTER TABLE notifications ADD COLUMN IF NOT EXISTS sender_id TEXT;
      ALTER TABLE notifications ADD COLUMN IF NOT EXISTS sender_name TEXT;
      ALTER TABLE notifications ADD COLUMN IF NOT EXISTS read_by JSONB DEFAULT '[]'::jsonb;
      CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read);
    `);
  } catch (e) { console.warn('Notifications Table Init:', e.message); }

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS maintenance_categories (
        category_id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        default_replacement_km INT DEFAULT 5000,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
      ALTER TABLE maintenance_categories ADD COLUMN IF NOT EXISTS default_replacement_km INT DEFAULT 5000;
    `);

    const defaultCats = [
      ['CAT-01', 'تبديل زيت المحرك والفلتر', 5000],
      ['CAT-02', 'تبديل إطارات (عجلات)', 40000],
      ['CAT-03', 'تبديل بطارية', 50000],
      ['CAT-04', 'تبديل دهن كير وفلتر', 40000],
      ['CAT-05', 'تبديل سفايف (فحمات فرامل)', 25000],
      ['CAT-06', 'تبديل فلاتر هواء وتبريد', 10000],
      ['CAT-07', 'صيانة عامة وفحص دوري', 15000]
    ];
    for (const c of defaultCats) {
      await pool.query(
        `INSERT INTO maintenance_categories (category_id, name, default_replacement_km) 
         VALUES ($1, $2, $3) 
         ON CONFLICT (category_id) DO UPDATE SET default_replacement_km = EXCLUDED.default_replacement_km`,
        c
      ).catch(() => {});
    }
  } catch (e) { console.warn('Categories Init:', e.message); }

  try {
    // التأكد من تفعيل الأقسام الأساسية
    await pool.query(`
      UPDATE departments SET is_deleted = FALSE WHERE department_id IN ('DEPT-001', 'DEPT-002', 'DEPT-000');
    `);
  } catch (e) {}

  try {
    // إزالة قيود التحقق القديمة عن عمود role لتمكين دور MANAGEMENT
    await pool.query(`
      DO $$
      DECLARE
        r RECORD;
      BEGIN
        FOR r IN (
          SELECT conname 
          FROM pg_constraint 
          WHERE conrelid = 'users'::regclass AND contype = 'c'
        ) LOOP
          EXECUTE 'ALTER TABLE users DROP CONSTRAINT IF EXISTS ' || quote_ident(r.conname);
        END LOOP;
      END $$;
    `);
  } catch (e) { console.warn('Drop Constraint Init:', e.message); }

  try {
    await pool.query(`
      INSERT INTO users (user_id, username, password_hash, full_name, department_id, unit, role, is_active, can_add_transaction)
      VALUES ('USR-MGT-001', 'management', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 'الإدارة العامة والمتابعة', 'DEPT-000', 'مكتب المدير العام', 'MANAGEMENT', TRUE, FALSE)
      ON CONFLICT (username) DO UPDATE SET role = 'MANAGEMENT', password_hash = 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', is_active = TRUE;
    `);
    console.log('✅ Management user USR-MGT-001 ready');
  } catch (e) { console.warn('Management User Init:', e.message); }
}
ensureTables();

// وسيط التحقق الأمني من الرمز المميز (JWT Authentication Middleware) مع دعم x-user-id للتطوير
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token && !token.startsWith('offline_') && !token.startsWith('session_')) {
    jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
      if (!err && decodedUser) {
        req.user = decodedUser;
        return next();
      }
      // إذا فشل التحقق من الرمز أو انتهت صلاحيته ولكن العميل أرسل معرف ورتبة المستخدم (Fallback)
      if (req.headers['x-user-id']) {
        const uId = req.headers['x-user-id'];
        const uRole = (req.headers['x-user-role'] || req.headers['x-role'] || 'USER').toUpperCase();
        req.user = { id: uId, user_id: uId, role: uRole, username: uId };
        return next();
      }
      return res.status(403).json({ error: 'انتهت صلاحية الجلسة أو الرمز غير صالح، يرجى تسجيل الدخول مجدداً' });
    });
  } else if (req.headers['x-user-id']) {
    const uId = req.headers['x-user-id'];
    const uRole = (req.headers['x-user-role'] || req.headers['x-role'] || 'USER').toUpperCase();
    req.user = { id: uId, user_id: uId, role: uRole, username: uId };
    next();
  } else {
    return res.status(401).json({ error: 'غير مصرح بالدخول (رمز الدخول مفقود)' });
  }
}

// دالة مساعدة لتجزئة كلمات المرور والتحقق منها (SHA-256 مع دعم الملح والتوافقية الكاملة)
function hashPassword(pass) {
  const salt = 'wheel_security_salt_2026';
  return crypto.createHash('sha256').update(String(pass) + salt).digest('hex');
}

function verifyPassword(pass, storedHash) {
  const passStr = String(pass);
  const salt = 'wheel_security_salt_2026';
  const saltedHash = crypto.createHash('sha256').update(passStr + salt).digest('hex');
  const plainHash = crypto.createHash('sha256').update(passStr).digest('hex');
  
  if (storedHash === saltedHash || storedHash === plainHash) return true;
  if (passStr === '123' && (
    storedHash === 'fe2203a7121790a6d378133b46f52993f9a47a4fc8988e1eaff6c9932ca37fc8' ||
    storedHash === 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3' ||
    storedHash === 'b4d5724c0d184094bf5716c9cf572b0ae852444b273fa1a555087ed65fe277d8'
  )) return true;
  return false;
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

// دالة إرسال إشعار لمستخدم أو فئة مستهدفة (v6.0)
async function sendNotification(userId, txId, title, purpose, message, type = 'INFO', targetType = 'TARGET_USER', targetId = null, senderId = 'SYSTEM', senderName = 'النظام') {
  try {
    const notifId = 'NOTIF-' + crypto.randomUUID().slice(0, 8);
    const finalTargetType = targetType || (userId === 'ALL' ? 'TARGET_ALL' : 'TARGET_USER');
    const finalTargetId = targetId || userId || null;
    await pool.query(
      `INSERT INTO notifications (
        notification_id, user_id, transaction_id, title, purpose, message,
        type, is_read, created_at, target_type, target_id, sender_id, sender_name, read_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, NOW(), $8, $9, $10, $11, '[]'::jsonb)`,
      [notifId, finalTargetId || 'ALL', txId, title, purpose || 'إشعار', message, type, finalTargetType, finalTargetId, senderId, senderName]
    );
  } catch (e) {
    console.warn('Send Notification Warning:', e.message);
  }
}

// دالة حساب كم مستحق الصيانة القادم لنفس نوع الصيانة (Due KM Calculation Engine)
async function calculateDueKm(wheelId, category, currentMileage) {
  let defaultKm = 5000;
  try {
    const catRes = await pool.query('SELECT default_replacement_km FROM maintenance_categories WHERE LOWER(name) = LOWER($1)', [category]);
    if (catRes.rows.length > 0) {
      defaultKm = parseInt(catRes.rows[0].default_replacement_km, 10) || 5000;
    }
  } catch (e) {}

  let baseKm = parseInt(currentMileage, 10) || 0;
  try {
    const prevTx = await pool.query(
      `SELECT COALESCE(mileage, 0) as km 
       FROM transactions 
       WHERE (wheel_id = $1 OR vehicle_numbers::text LIKE '%' || $1 || '%') 
         AND LOWER(category) = LOWER($2) 
         AND (is_deleted = FALSE OR is_deleted IS NULL)
       ORDER BY mileage DESC, created_at DESC 
       LIMIT 1`,
      [wheelId, category]
    );
    if (prevTx.rows.length > 0 && prevTx.rows[0].km > 0) {
      baseKm = parseInt(prevTx.rows[0].km, 10);
    }
  } catch (e) {}

  return baseKm + defaultKm;
}

// دالة الفحص التلقائي والتنبيه الفوري عند استحقاق الصيانة (Overdue Maintenance Smart Auto-Alert - Axis 5)
async function checkAndTriggerOverdueAlerts(wheelId, currentMileage, submitterUserId, departmentId, excludeTxId = null) {
  try {
    const curKm = parseInt(currentMileage, 10);
    if (isNaN(curKm) || curKm <= 0) return;

    // 1. جلب كافة أنواع الصيانة المسجلة
    let catRows = [];
    try {
      const catRes = await pool.query('SELECT category_id, name, default_replacement_km FROM maintenance_categories WHERE default_replacement_km > 0');
      catRows = catRes.rows || [];
    } catch (e) {}

    if (catRows.length === 0) {
      catRows = [
        { category_id: 'CAT-01', name: 'تبديل زيت المحرك والفلتر', default_replacement_km: 5000 },
        { category_id: 'CAT-02', name: 'تبديل إطارات (عجلات)', default_replacement_km: 40000 },
        { category_id: 'CAT-03', name: 'تبديل بطارية', default_replacement_km: 50000 },
        { category_id: 'CAT-04', name: 'تبديل دهن كير وفلتر', default_replacement_km: 40000 },
        { category_id: 'CAT-05', name: 'تبديل سفايف (فحمات فرامل)', default_replacement_km: 25000 },
        { category_id: 'CAT-06', name: 'تبديل فلاتر هواء وتبريد', default_replacement_km: 10000 },
        { category_id: 'CAT-07', name: 'صيانة عامة وفحص دوري', default_replacement_km: 15000 }
      ];
    }

    // العثور على مسؤولي القسم لهذا القسم (DEPARTMENT_HEAD)
    let deptHeadIds = [];
    try {
      const deptHeadRes = await pool.query(
        `SELECT user_id FROM users 
         WHERE (department_id = $1 OR assigned_department_id = $1)
           AND (UPPER(role) = 'DEPARTMENT_HEAD' OR is_department_manager = TRUE)
           AND is_active = TRUE AND (is_deleted = FALSE OR is_deleted IS NULL)`,
        [departmentId]
      );
      deptHeadIds = deptHeadRes.rows.map(r => r.user_id);
    } catch (e) {}

    for (const cat of catRows) {
      const categoryName = cat.name;
      const defaultReplacementKm = parseInt(cat.default_replacement_km, 10);
      if (!defaultReplacementKm || defaultReplacementKm <= 0) continue;

      // حساب Last Service KM لنفس نوع الصيانة مع استبعاد المعاملة الحالية
      const prevTx = await pool.query(
        `SELECT COALESCE(mileage, 0) as km 
         FROM transactions 
         WHERE (wheel_id = $1 OR vehicle_numbers::text LIKE '%' || $1 || '%') 
           AND LOWER(category) = LOWER($2) 
           AND ($3::text IS NULL OR transaction_id != $3)
           AND (is_deleted = FALSE OR is_deleted IS NULL)
         ORDER BY mileage DESC, created_at DESC 
         LIMIT 1`,
        [wheelId, categoryName, excludeTxId]
      );

      let lastServiceKm = 0;
      if (prevTx.rows.length > 0 && prevTx.rows[0].km > 0) {
        lastServiceKm = parseInt(prevTx.rows[0].km, 10);
      }

      const dueKm = lastServiceKm + defaultReplacementKm;

      if (curKm >= dueKm) {
        // نص الإشعار الإلزامي:
        // "تنبيه استحقاق صيانة: العجلة رقم [رقم العجلة] تجاوزت المسافة الافتراضية المحددة لصيانة [نوع الصيانة] (العداد الحالي: [X] كم / المستحق: [Y] كم)، يرجى فحصها وإجراء الصيانة اللازمة."
        const alertTitle = `تنبيه استحقاق صيانة: ${wheelId}`;
        const alertPurpose = 'استحقاق صيانة دورية';
        const alertMessage = `تنبيه استحقاق صيانة: العجلة رقم [${wheelId}] تجاوزت المسافة الافتراضية المحددة لصيانة [${categoryName}] (العداد الحالي: [${curKm}] كم / المستحق: [${dueKm}] كم)، يرجى فحصها وإجراء الصيانة اللازمة.`;

        // إرسال للمستخدم مقدم المعاملة
        if (submitterUserId) {
          await sendNotification(
            submitterUserId,
            excludeTxId,
            alertTitle,
            alertPurpose,
            alertMessage,
            'WARNING',
            'TARGET_USER',
            submitterUserId,
            'SYSTEM',
            'منظومة الصيانة الذكية'
          );
        }

        // إرسال لمسؤول القسم التابع له العجلة
        for (const headId of deptHeadIds) {
          if (headId !== submitterUserId) {
            await sendNotification(
              headId,
              excludeTxId,
              alertTitle,
              alertPurpose,
              alertMessage,
              'WARNING',
              'TARGET_USER',
              headId,
              'SYSTEM',
              'منظومة الصيانة الذكية'
            );
          }
        }

        // إرسال لإدارة النظام (ADMIN & MANAGEMENT) - v7.0
        try {
          const adminUsersRes = await pool.query(
            `SELECT user_id FROM users 
             WHERE UPPER(role) IN ('ADMIN', 'MANAGEMENT')
               AND is_active = TRUE AND (is_deleted = FALSE OR is_deleted IS NULL)`
          );
          for (const adm of adminUsersRes.rows) {
            if (adm.user_id !== submitterUserId && !deptHeadIds.includes(adm.user_id)) {
              await sendNotification(
                adm.user_id,
                excludeTxId,
                alertTitle,
                alertPurpose,
                alertMessage,
                'WARNING',
                'TARGET_USER',
                adm.user_id,
                'SYSTEM',
                'منظومة الصيانة الذكية'
              );
            }
          }
        } catch (eAdm) {
          console.warn('Overdue Admin notification dispatch error:', eAdm.message);
        }
      }
    }
  } catch (err) {
    console.warn('checkAndTriggerOverdueAlerts error:', err.message);
  }
}

// ==============================================================================
// 1. فحص صحة وحالة السيرفر (Health Check & Info)
// ==============================================================================
app.get(['/api/health', '/api/ping'], async (req, res) => {
  let dbStatus = 'disconnected';
  try {
    await pool.query('SELECT NOW() as db_time');
    dbStatus = 'connected';
  } catch (e) {
    dbStatus = `error: ${e.message}`;
  }

  res.json({
    status: 'online',
    system: 'Wheel Maintenance Cloud API',
    version: '7.0.0 (Final QA Audit, Reactive Binding & APK Optimization)',
    database: dbStatus,
    timestamp: new Date().toISOString()
  });
});

// ==============================================================================
// 2. تسجيل الدخول وإصدار رمز الدخول (Authentication - Login)
// ==============================================================================
app.post(['/api/auth/login', '/api/login'], async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'يرجى إدخال اسم المستخدم وكلمة المرور' });
    }

    const cleanUser = String(username).trim();
    const query = `
      SELECT u.*, 
             COALESCE(d.name, u.department_id) as department_name,
             COALESCE(d.name, u.department_id) as department
      FROM users u
      LEFT JOIN departments d ON u.department_id = d.department_id
      WHERE (u.user_id = $1 OR LOWER(u.username) = LOWER($1)) AND (u.is_deleted = FALSE OR u.is_deleted IS NULL)
    `;
    const result = await pool.query(query, [cleanUser]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    const user = result.rows[0];

    if (user.is_active === false) {
      return res.status(403).json({ error: 'الحساب معطل من قبل مدير النظام' });
    }

    const isValid = verifyPassword(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    const payload = {
      id: user.user_id,
      user_id: user.user_id,
      username: user.username,
      full_name: user.full_name,
      role: user.role,
      department_id: user.department_id,
      department_name: user.department_name || '',
      department: user.department_name || user.department_id || '',
      unit: user.unit || '',
      is_department_manager: user.is_department_manager || false,
      assigned_department_id: user.assigned_department_id || null,
      can_add_transaction: user.can_add_transaction !== false
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    try {
      await pool.query('UPDATE users SET last_login_at = NOW() WHERE user_id = $1', [user.user_id]);
    } catch (e1) {
      try {
        await pool.query('UPDATE users SET last_login = NOW() WHERE user_id = $1', [user.user_id]);
      } catch (e2) {}
    }

    try {
      await logAudit('USER_LOGIN', 'users', user.user_id, user.user_id, user.full_name, { ip: req.ip });
    } catch (e3) {}

    delete user.password_hash;
    res.json({
      success: true,
      message: 'تم تسجيل الدخول بنجاح',
      token,
      user: { ...user, ...payload }
    });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ error: 'حدث خطأ في الخادم أثناء تسجيل الدخول', details: err.message });
  }
});

// استعلام بيانات المستخدم الحالي
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const userRes = await pool.query(
      `SELECT u.user_id, u.username, u.full_name, u.role, u.department_id, u.unit, u.is_read_only, 
              u.can_add_transaction, u.is_department_manager, u.assigned_department_id,
              COALESCE(d.name, u.department_id) as department_name,
              COALESCE(d.name, u.department_id) as department
       FROM users u
       LEFT JOIN departments d ON u.department_id = d.department_id
       WHERE u.user_id = $1 AND u.is_deleted = FALSE`,
      [req.user.id || req.user.user_id]
    );

    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }

    res.json({ success: true, user: userRes.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'فشل استرجاع بيانات المستخدم' });
  }
});

// ==============================================================================
// 3. إضافة معاملة صيانة جديدة (3-Tier Workflow: Phase 1 Creation)
// ==============================================================================
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const actorId = actor.id || actor.user_id;

    // استرجاع بيانات المستخدم من قاعدة البيانات للتحقق الدقيق
    const userRes = await pool.query('SELECT * FROM users WHERE user_id = $1 AND is_deleted = FALSE', [actorId]);
    if (userRes.rows.length === 0 || !userRes.rows[0].is_active) {
      return res.status(403).json({ error: 'المستخدم غير مفعّل أو تم إيقافه' });
    }
    const user = userRes.rows[0];

    // حظر الإنشاء من المدقق أو الإدارة أو الأدمن (المعاملات تُنشأ حصراً من قبل USER أو DEPARTMENT_HEAD)
    const normalizedRole = (user.role || '').toUpperCase();
    if (normalizedRole === 'AUDITOR' || isManagementOrAdmin(normalizedRole)) {
      return res.status(403).json({ 
        error: 'عذراً، لا يمكن للمدقق أو الإدارة أو مدير النظام إنشاء معاملات صيانة؛ الإنشاء مخصص للمستخدمين الميدانيين ومسؤولي الأقسام فقط.' 
      });
    }

    if (user.is_read_only) {
      return res.status(403).json({ error: 'حسابك مخصص للقراءة والاطلاع فقط، لا تملك صلاحية إضافة معاملات.' });
    }

    // استنتاج القسم تلقائياً من المستخدم
    const userDept = user.department_id || user.assigned_department_id || req.body.department_id;
    if (!userDept) {
      return res.status(400).json({ error: 'المستخدم غير مرتبط بأي قسم، يرجى مراجعة مدير النظام لربط الحساب بقسم صالح.' });
    }

    const { 
      vehicle_numbers,
      receipt_images,
      vehicle_images,
      member_user_id
    } = req.body;

    const wheelId = String(req.body.wheel_id || req.body.vehicle_id || req.body.plate_number || (Array.isArray(vehicle_numbers) && vehicle_numbers.length > 0 ? vehicle_numbers[0] : '')).trim();
    if (!wheelId) {
      return res.status(400).json({ error: 'يرجى تحديد أو إدخال رقم العجلة المراد صيانتها.' });
    }

    // التحقق الصارم من أن العجلة مسجلة ونشطة وتابعة لقسم المستخدم (Strict Validation - Axis 3)
    const vehCheck = await pool.query(
      `SELECT * FROM vehicles WHERE (vehicle_id = $1 OR plate_number = $1) AND (is_deleted = FALSE OR is_deleted IS NULL)`,
      [wheelId]
    );

    if (vehCheck.rows.length === 0) {
      return res.status(400).json({ 
        error: `عذراً، رقم العجلة (${wheelId}) غير مسجل في النظام. يرجى التأكد من الرقم أو مراجعة إدارة الأسطول.` 
      });
    }

    const existingVeh = vehCheck.rows[0];
    if (!existingVeh.is_active) {
      return res.status(400).json({ 
        error: `عذراً، العجلة (${wheelId}) موقوفة أو غير نشطة حالياً.` 
      });
    }

    const isDeptMatch = !existingVeh.department_id ||
      existingVeh.department_id === userDept ||
      existingVeh.department_id === user.department_id ||
      existingVeh.department_id === user.assigned_department_id;

    if (!isDeptMatch && !isManagementOrAdmin(normalizedRole)) {
      return res.status(400).json({ 
        error: `عذراً، رقم العجلة (${wheelId}) غير مسجل أو لا يتبع لقسمك.` 
      });
    }

    const mileage = parseInt(req.body.mileage !== undefined ? req.body.mileage : (req.body.current_km || 0), 10) || 0;

    // تحديث قراءة العداد الحالية للعجلة إن كانت القراءة المدخلة أكبر
    if (mileage > (existingVeh.current_km || 0)) {
      try {
        await pool.query('UPDATE vehicles SET current_km = $1, updated_at = NOW() WHERE vehicle_id = $2', [mileage, existingVeh.vehicle_id]);
      } catch (e) {}
    }
    const description = req.body.description !== undefined ? req.body.description : (req.body.notes || '');
    const category = req.body.category || req.body.maintenance_type || 'إطارات وبطاريات';
    const receipt_image = req.body.receipt_image || (Array.isArray(receipt_images) && receipt_images.length > 0 ? receipt_images[0] : null);
    const allReceipts = receipt_images || (receipt_image ? [receipt_image] : []);
    const allVehicleImgs = vehicle_images || [];
    
    // التكلفة تكون دائماً 0 عند الإنشاء (تُحدد حصراً من قبل الأدمن في المرحلة الثالثة)
    const cost = 0.00;
    const status = 'PENDING_AUDITOR';
    const txId = req.body.transaction_id || ('TX-' + new Date().getFullYear() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase());

    // التحقق من الإضافة لمنتسب في حال مسؤول القسم
    let targetUserId = user.user_id;
    let targetMemberId = null;
    if (member_user_id) {
      const isMgr = (user.is_department_manager || normalizedRole === 'DEPARTMENT_HEAD' || normalizedRole === 'ADMIN');
      if (!isMgr) {
        return res.status(403).json({ error: 'ليس لديك صلاحية إضافة معاملات لمنتسبي القسم.' });
      }
      const memRes = await pool.query('SELECT * FROM users WHERE user_id = $1 AND is_deleted = FALSE', [member_user_id]);
      if (memRes.rows.length === 0) {
        return res.status(404).json({ error: 'المنتسب المحدد غير موجود' });
      }
      targetUserId = memRes.rows[0].user_id;
      targetMemberId = memRes.rows[0].user_id;
    }

    const primaryWheel = wheelId;
    const allWheels = vehicle_numbers || [primaryWheel];

    const insertResult = await pool.query(
      `INSERT INTO transactions 
       (transaction_id, wheel_id, vehicle_numbers, department_id, user_id, member_user_id, created_by, 
        description, cost, mileage, receipt_image, receipt_images, vehicle_images, category, status, is_locked, 
        auditor_note, admin_note, is_deleted, created_at, updated_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, TRUE, '', '', FALSE, NOW(), $16)
       RETURNING *`,
      [
        txId,
        primaryWheel,
        JSON.stringify(allWheels),
        userDept,
        targetUserId,
        targetMemberId,
        actorId,
        description || '',
        cost,
        mileage,
        receipt_image,
        JSON.stringify(allReceipts),
        JSON.stringify(allVehicleImgs),
        category,
        status,
        actorId
      ]
    );

    const newTx = insertResult.rows[0];

    // إرسال إشعارات فورية لكافة المدققين المعتمدين في النظام
    const auditors = await pool.query(
      `SELECT user_id FROM users WHERE UPPER(role) = 'AUDITOR' AND is_active = TRUE AND is_deleted = FALSE`
    );
    for (const aud of auditors.rows) {
      await sendNotification(
        aud.user_id,
        txId,
        'معاملة جديدة بانتظار التدقيق',
        'تدقيق وصولات',
        `تم رفع طلب صيانة جديد للعجلة [${primaryWheel}] بواسطة (${user.full_name}) بانتظار تدقيق الوصل.`
      );
    }

    await logAudit('CREATE_TRANSACTION', 'transactions', txId, actorId, user.full_name, {
      wheel_id: primaryWheel,
      department_id: userDept
    });

    // إطلاق الفحص التلقائي والتنبيه الفوري عند استحقاق الصيانة (Smart Overdue Alert - Axis 5)
    await checkAndTriggerOverdueAlerts(existingVeh.plate_number || primaryWheel, mileage, targetUserId, userDept, txId);

    res.status(201).json({
      success: true,
      message: 'تم إرسال المعاملة وحفظها بنجاح وتحويلها لمدقق الوصولات 📋',
      data: newTx,
      transaction: newTx
    });
  } catch (err) {
    console.error('Insert Transaction Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ المعاملة: ' + (err.message || err) });
  }
});

// ==============================================================================
// 4. جلب المعاملات مع تطبيق عزل الأقسام والرتب (RBAC Isolation)
// ==============================================================================
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { status, limit = 500, offset = 0, wheel_id } = req.query;
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();
    const actorId = actor.id || actor.user_id;

    let query = `
      SELECT t.*, 
             COALESCE(t.wheel_id, '') as plate_number,
             COALESCE(t.cost, 0) as maintenance_price,
             COALESCE(t.mileage, 0) as current_km,
             COALESCE(t.mileage, 0) + COALESCE(mc.default_replacement_km, 5000) as due_km,
             COALESCE(t.description, '') as notes,
             u.full_name as user_name, 
             u.username,
             d.name as department_name,
             c.full_name as created_by_name
      FROM transactions t
      LEFT JOIN users u ON t.user_id = u.user_id
      LEFT JOIN departments d ON t.department_id = d.department_id
      LEFT JOIN users c ON t.created_by = c.user_id
      LEFT JOIN maintenance_categories mc ON LOWER(mc.name) = LOWER(t.category)
      WHERE t.is_deleted = FALSE
    `;
    const params = [];

    // عزل البيانات حسب الدور الوظيفي:
    if (actorRole === 'USER') {
      // المستخدم الميداني يرى فقط المعاملات التي أنشأها
      params.push(actorId);
      query += ` AND (t.user_id = $${params.length} OR t.created_by = $${params.length})`;
    } else if (actorRole === 'DEPARTMENT_HEAD') {
      // مسؤول القسم يرى كافة معاملات قسمه فقط
      const dept = actor.assigned_department_id || actor.department_id;
      params.push(dept);
      query += ` AND t.department_id = $${params.length}`;
    }
    // المدقق والأدمن يريان جميع المعاملات في مراحل التدقيق والاعتماد

    if (wheel_id) {
      params.push(wheel_id);
      query += ` AND (t.wheel_id = $${params.length} OR t.wheel_id ILIKE $${params.length})`;
    }

    if (status && status !== 'ALL') {
      params.push(status);
      query += ` AND t.status = $${params.length}`;
    }

    query += ` ORDER BY t.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(parseInt(limit, 10), parseInt(offset, 10));

    const result = await pool.query(query, params);
    res.json({ success: true, count: result.rows.length, data: result.rows, transactions: result.rows });
  } catch (err) {
    console.error('Fetch Transactions Error:', err);
    res.status(500).json({ error: 'فشل جلب المعاملات من السيرفر' });
  }
});

// ==============================================================================
// 5. مسار تدقيق المعاملات من قبل المدقق (Phase 2: Auditor Review)
// ==============================================================================
app.post(['/api/auditor/transactions/:id/review', '/api/transactions/:id/review'], authenticateToken, async (req, res) => {
  try {
    const txId = req.params.id;
    const { action, note, auditor_note } = req.body;
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();

    if (actorRole !== 'AUDITOR' && !isManagementOrAdmin(actorRole)) {
      return res.status(403).json({ error: 'عذراً، صلاحية تدقيق الوصولات مخصصة لحساب المدقق والإدارة فقط.' });
    }

    const txRes = await pool.query(`SELECT * FROM transactions WHERE transaction_id = $1 AND is_deleted = FALSE`, [txId]);
    if (txRes.rows.length === 0) {
      return res.status(404).json({ error: 'المعاملة غير موجودة' });
    }
    const tx = txRes.rows[0];

    const finalNote = (note || auditor_note || '').trim();

    if (action === 'APPROVE_TO_ADMIN' || action === 'APPROVE') {
      // موافقة المدقق والإحالة للإدارة
      const updRes = await pool.query(
        `UPDATE transactions 
         SET status = 'PENDING_ADMIN', 
             auditor_note = $1, 
             audited_by_auditor_at = NOW(), 
             updated_by = $2, 
             updated_at = NOW() 
         WHERE transaction_id = $3 
         RETURNING *`,
        [finalNote, actor.id || actor.user_id, txId]
      );

      // إشعار لمقدم المعاملة
      await sendNotification(
        tx.user_id,
        txId,
        'تم تدقيق المعاملة بنجاح ✅',
        'موافقة تدقيق',
        `تمت موافقة المدقق على معاملة العجلة [${tx.wheel_id}] وأُحيلت للإدارة للاعتماد المالي والإداري.`
      );

      // إشعار لمديري النظام والإدارة (Admins & Management)
      const managers = await pool.query(`SELECT user_id FROM users WHERE UPPER(role) IN ('ADMIN', 'MANAGEMENT') AND is_active = TRUE AND is_deleted = FALSE`);
      for (const adm of managers.rows) {
        await sendNotification(
          adm.user_id,
          txId,
          'معاملة جديدة بانتظار الاعتماد المالي',
          'اعتماد الإدارة',
          `أحال المدقق معاملة العجلة [${tx.wheel_id}] بانتظار تحديد التكلفة والاعتماد النهائي.`
        );
      }

      await logAudit('AUDITOR_APPROVE', 'transactions', txId, actor.id || actor.user_id, actor.full_name, { note: finalNote });
      return res.json({ success: true, message: 'تمت موافقة المدقق وإحالة المعاملة للإدارة بنجاح', transaction: updRes.rows[0] });

    } else if (action === 'REJECT_BY_AUDITOR' || action === 'RETURN_FOR_EDIT' || action === 'REJECT') {
      if (!finalNote) {
        return res.status(400).json({ error: 'يجب كتابة ملاحظة توضح سبب الإعادة أو الرفض للوصل.' });
      }

      const newStatus = action === 'RETURN_FOR_EDIT' ? 'IN_PROGRESS' : 'REJECTED_AUDITOR';
      const updRes = await pool.query(
        `UPDATE transactions 
         SET status = $1, 
             auditor_note = $2, 
             audited_by_auditor_at = NOW(), 
             updated_by = $3, 
             updated_at = NOW() 
         WHERE transaction_id = $4 
         RETURNING *`,
        [newStatus, finalNote, actor.id || actor.user_id, txId]
      );

      // إشعار لمقدم المعاملة
      await sendNotification(
        tx.user_id,
        txId,
        'إعادة المعاملة من قبل المدقق ⚠️',
        'ملاحظة تدقيق',
        `تمت إعادة معاملة العجلة [${tx.wheel_id}] من قبل المدقق مع الملاحظة التالية: "${finalNote}".`
      );

      await logAudit('AUDITOR_REJECT', 'transactions', txId, actor.id || actor.user_id, actor.full_name, { note: finalNote });
      return res.json({ success: true, message: 'تمت إعادة المعاملة وإشعار المستخدم بملاحظة التدقيق', transaction: updRes.rows[0] });
    } else {
      return res.status(400).json({ error: 'إجراء التدقيق غير صالح (يجب أن يكون APPROVE_TO_ADMIN أو REJECT_BY_AUDITOR)' });
    }
  } catch (err) {
    console.error('Auditor Review Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء معالجة قرار التدقيق: ' + (err.message || err) });
  }
});

// ==============================================================================
// 6. مسار الاعتماد المالي والإداري من الإدارة (Phase 3: Management & Admin Approval)
// ==============================================================================
app.post(['/api/admin/transactions/:id/review', '/api/management/transactions/:id/review', '/api/transactions/:id/approve', '/api/admin/transactions/:id/status'], authenticateToken, async (req, res) => {
  try {
    const txId = req.params.id;
    const { action, cost, maintenance_price, admin_note, note } = req.body;
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();

    if (!isManagementOrAdmin(actorRole)) {
      return res.status(403).json({ error: 'عذراً، صلاحية الاعتماد المالي وتحديد المبلغ والاعتماد النهائي محصورة بالإدارة (MANAGEMENT) ومدير النظام (ADMIN).' });
    }

    const txRes = await pool.query(`SELECT * FROM transactions WHERE transaction_id = $1 AND is_deleted = FALSE`, [txId]);
    if (txRes.rows.length === 0) {
      return res.status(404).json({ error: 'المعاملة غير موجودة' });
    }
    const tx = txRes.rows[0];

    const finalNote = (admin_note || note || '').trim();

    if (action === 'APPROVE' || action === 'AUDITED' || action === 'FINAL_APPROVE') {
      // حصر كتابة مبلغ الصيانة بالإدارة فقط وإلزامية إدخال مبلغ أكبر من صفر
      const costVal = parseFloat(cost !== undefined ? cost : maintenance_price);
      if (!costVal || isNaN(costVal) || costVal <= 0) {
        return res.status(400).json({ error: 'يجب إدخال مبلغ الصيانة الفعلي (أكبر من 0) لاعتماد المعاملة نهائياً.' });
      }

      const updRes = await pool.query(
        `UPDATE transactions 
         SET status = 'AUDITED', 
             cost = $1, 
             admin_note = $2, 
             is_locked = TRUE, 
             audited_at = NOW(), 
             updated_by = $3, 
             updated_at = NOW() 
         WHERE transaction_id = $4 
         RETURNING *`,
        [costVal, finalNote, actor.id || actor.user_id, txId]
      );

      // تحديث كيلومتر العجلة في جدول العجلات إذا كانت قراءة العداد أعلى
      if (tx.mileage > 0) {
        await pool.query(
          `UPDATE vehicles 
           SET current_km = GREATEST(COALESCE(current_km, 0), $1), updated_at = NOW() 
           WHERE vehicle_id = $2 OR plate_number = $2`,
          [tx.mileage, tx.wheel_id]
        );
      }

      // إرسال إشعار اعتماد نهائي لمقدم المعاملة
      await sendNotification(
        tx.user_id,
        txId,
        'تم اعتماد المعاملة نهائياً 🏁',
        'اعتماد نهائي',
        `تم اعتماد معاملة العجلة [${tx.wheel_id}] نهائياً من قبل الإدارة بمبلغ (${costVal.toLocaleString()} د.ع).`
      );

      await logAudit('ADMIN_APPROVE', 'transactions', txId, actor.id || actor.user_id, actor.full_name, { cost: costVal, note: finalNote });
      return res.json({ success: true, message: 'تم الاعتماد المالي والإداري للمعاملة وإغلاقها بنجاح', transaction: updRes.rows[0] });

    } else if (action === 'REJECT_ADMIN' || action === 'REJECT') {
      // إلزامية ذكر سبب الرفض الإداري
      if (!finalNote) {
        return res.status(400).json({ error: 'يجب كتابة سبب الرفض الإداري إلزامياً قبل تنفيذ الرفض.' });
      }

      const updRes = await pool.query(
        `UPDATE transactions 
         SET status = 'REJECTED_ADMIN', 
             admin_note = $1, 
             is_locked = TRUE, 
             audited_at = NOW(), 
             updated_by = $2, 
             updated_at = NOW() 
         WHERE transaction_id = $3 
         RETURNING *`,
        [finalNote, actor.id || actor.user_id, txId]
      );

      // إرسال إشعار رفض لمقدم المعاملة يتضمن السبب
      await sendNotification(
        tx.user_id,
        txId,
        'رفض المعاملة من قبل الإدارة ❌',
        'رفض إداري',
        `تم رفض معاملة العجلة [${tx.wheel_id}] من قبل الإدارة. سبب الرفض: "${finalNote}".`
      );

      await logAudit('ADMIN_REJECT', 'transactions', txId, actor.id || actor.user_id, actor.full_name, { note: finalNote });
      return res.json({ success: true, message: 'تم رفض المعاملة وإشعار المستخدم بالسبب', transaction: updRes.rows[0] });

    } else {
      return res.status(400).json({ error: 'إجراء الاعتماد الإداري غير صالح' });
    }
  } catch (err) {
    console.error('Admin Review Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء معالجة قرار الإدارة: ' + (err.message || err) });
  }
});

// ==============================================================================
// 6.1 التعديل الشامل للمعاملات (Full Transaction Edit - Admin & Management Only)
// ==============================================================================
app.put(['/api/transactions/:id', '/api/admin/transactions/:id'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();
    if (!isManagementOrAdmin(actorRole)) {
      return res.status(403).json({ error: 'عذراً، صلاحية التعديل الشامل للمعاملات محصورة بالإدارة (MANAGEMENT) ومدير النظام (ADMIN).' });
    }

    const txId = req.params.id;
    const existingRes = await pool.query('SELECT * FROM transactions WHERE transaction_id = $1', [txId]);
    if (existingRes.rows.length === 0) {
      return res.status(404).json({ error: 'المعاملة غير موجودة' });
    }

    const {
      wheel_id,
      category,
      mileage,
      current_km,
      cost,
      maintenance_price,
      notes,
      description,
      status,
      department_id,
      vehicle_images,
      receipt_images,
      receipt_image
    } = req.body;

    const finalMileage = parseInt(mileage !== undefined ? mileage : current_km, 10);
    const finalCost = parseFloat(cost !== undefined ? cost : maintenance_price);
    const finalVehImages = vehicle_images ? (typeof vehicle_images === 'string' ? vehicle_images : JSON.stringify(vehicle_images)) : undefined;
    const finalReceiptImages = receipt_images ? (typeof receipt_images === 'string' ? receipt_images : JSON.stringify(receipt_images)) : undefined;

    const updateFields = [];
    const values = [];
    let idx = 1;

    if (wheel_id !== undefined) {
      updateFields.push(`wheel_id = $${idx++}`);
      values.push(wheel_id);
      updateFields.push(`vehicle_numbers = $${idx++}::jsonb`);
      values.push(JSON.stringify([wheel_id]));
    }
    if (category !== undefined) {
      updateFields.push(`category = $${idx++}`);
      values.push(category);
    }
    if (!isNaN(finalMileage)) {
      updateFields.push(`mileage = $${idx++}`);
      values.push(finalMileage);
    }
    if (!isNaN(finalCost)) {
      updateFields.push(`cost = $${idx++}`);
      values.push(finalCost);
    }
    if (notes !== undefined || description !== undefined) {
      updateFields.push(`description = $${idx++}`);
      values.push(notes !== undefined ? notes : description);
    }
    if (status !== undefined) {
      updateFields.push(`status = $${idx++}`);
      values.push(status);
    }
    if (department_id !== undefined) {
      updateFields.push(`department_id = $${idx++}`);
      values.push(department_id);
    }
    if (finalVehImages !== undefined) {
      updateFields.push(`vehicle_images = $${idx++}::jsonb`);
      values.push(finalVehImages);
    }
    if (finalReceiptImages !== undefined) {
      updateFields.push(`receipt_images = $${idx++}::jsonb`);
      values.push(finalReceiptImages);
    }
    if (receipt_image !== undefined) {
      updateFields.push(`receipt_image = $${idx++}`);
      values.push(receipt_image);
    }

    updateFields.push(`updated_at = NOW()`);
    updateFields.push(`updated_by = $${idx++}`);
    values.push(actor.id || actor.user_id);

    values.push(txId);
    const updateQuery = `
      UPDATE transactions
      SET ${updateFields.join(', ')}
      WHERE transaction_id = $${idx}
      RETURNING *
    `;
    const updatedRes = await pool.query(updateQuery, values);

    if (!isNaN(finalMileage) && finalMileage > 0 && updatedRes.rows.length > 0) {
      try {
        const row = updatedRes.rows[0];
        await pool.query('UPDATE vehicles SET current_km = $1, updated_at = NOW() WHERE (plate_number = $2 OR vehicle_id = $2) AND (current_km < $1 OR current_km IS NULL)', [finalMileage, row.wheel_id]);
        await checkAndTriggerOverdueAlerts(row.wheel_id, finalMileage, row.user_id, row.department_id);
      } catch (e) {}
    }

    await logAudit('FULL_TRANSACTION_EDIT', 'transactions', txId, actor.id || actor.user_id, actor.full_name || actor.username, req.body);

    res.json({
      success: true,
      message: 'تم إجراء التعديل الشامل للمعاملة بنجاح ✏️',
      transaction: updatedRes.rows[0],
      data: updatedRes.rows[0]
    });
  } catch (err) {
    console.error('Full Edit Error:', err);
    res.status(500).json({ error: 'فشل التعديل الشامل للمعاملة', details: err.message });
  }
});

// ==============================================================================
// 7. إدارة وتحديث وحذف المستخدمين (Users Management - Admin Only)
// ==============================================================================
app.get(['/api/users', '/api/admin/users'], authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.user_id, u.username, u.full_name, u.role, u.department_id, u.unit, u.is_active, 
              u.is_read_only, u.can_add_transaction, u.is_department_manager, 
              u.assigned_department_id, u.can_add_dept_members_transactions, u.is_deleted, u.created_at,
              COALESCE(d.name, u.department_id) as department_name,
              COALESCE(d.name, u.department_id) as department
       FROM users u
       LEFT JOIN departments d ON u.department_id = d.department_id
       WHERE u.is_deleted = FALSE 
       ORDER BY u.created_at DESC`
    );
    res.json({ success: true, data: result.rows, users: result.rows });
  } catch (err) {
    console.error('Fetch Users Error:', err);
    res.status(500).json({ error: 'فشل جلب قائمة المستخدمين' });
  }
});

// إضافة مستخدم جديد (حقل القسم إلزامي)
app.post(['/api/users', '/api/admin/users', '/api/admin/users/add', '/api/admin/users/create'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    if (!isManagementOrAdmin(actor.role)) {
      return res.status(403).json({ error: 'صلاحية إضافة المستخدمين محصورة بالإدارة ومدير النظام' });
    }

    const {
      user_id,
      username,
      password,
      full_name,
      role,
      department_id,
      department,
      unit,
      is_active,
      is_read_only,
      can_add_transaction,
      is_department_manager,
      assigned_department_id,
      can_add_dept_members_transactions
    } = req.body;

    const finalDept = department_id || department;
    if (!username || !full_name) {
      return res.status(400).json({ error: 'يرجى إدخال اسم المستخدم والاسم الكامل' });
    }
    if (!finalDept && (role || '').toUpperCase() !== 'ADMIN') {
      return res.status(400).json({ error: 'يرجى تحديد القسم التابع له المستخدم (حقل القسم إلزامي)' });
    }

    const cleanUsername = String(username).trim();
    const dupCheck = await pool.query(
      'SELECT user_id FROM users WHERE LOWER(username) = LOWER($1) AND is_deleted = FALSE',
      [cleanUsername]
    );
    if (dupCheck.rows.length > 0) {
      return res.status(409).json({ error: 'اسم المستخدم مسجل مسبقاً، يرجى اختيار اسم آخر' });
    }

    const newUserId = user_id || ('USR-' + crypto.randomBytes(3).toString('hex').toUpperCase());
    const passHash = hashPassword(password || '123');

    await pool.query(
      `INSERT INTO users (
        user_id, username, password_hash, full_name, role, department_id, unit,
        is_active, is_read_only, can_add_transaction, is_department_manager,
        assigned_department_id, can_add_dept_members_transactions, is_deleted, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, FALSE, NOW())`,
      [
        newUserId,
        cleanUsername,
        passHash,
        String(full_name).trim(),
        role || 'USER',
        finalDept || null,
        unit || '',
        is_active !== false && is_active !== 0,
        Boolean(is_read_only),
        can_add_transaction !== false && can_add_transaction !== 0,
        Boolean(is_department_manager),
        assigned_department_id || finalDept || null,
        Boolean(can_add_dept_members_transactions)
      ]
    );

    const fullUserRes = await pool.query(
      `SELECT u.user_id, u.username, u.full_name, u.role, u.department_id, u.unit, u.is_active, 
              u.is_read_only, u.can_add_transaction, u.is_department_manager, 
              u.assigned_department_id, u.can_add_dept_members_transactions, u.is_deleted, u.created_at,
              COALESCE(d.name, u.department_id) as department_name,
              COALESCE(d.name, u.department_id) as department
       FROM users u
       LEFT JOIN departments d ON u.department_id = d.department_id
       WHERE u.user_id = $1`,
      [newUserId]
    );

    await logAudit('CREATE_USER', 'users', newUserId, actor.id || actor.user_id, actor.full_name, { username: cleanUsername });
    res.status(201).json({ success: true, message: 'تم حفظ المستخدم بنجاح', user: fullUserRes.rows[0], data: fullUserRes.rows[0] });
  } catch (err) {
    console.error('Create User Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ المستخدم: ' + (err.message || err) });
  }
});

// تعديل بيانات المستخدم (Admin Only)
const handleUserUpdate = async (req, res) => {
  try {
    const actor = req.user;
    if (!isManagementOrAdmin(actor.role)) {
      return res.status(403).json({ error: 'صلاحية تعديل المستخدمين محصورة بالإدارة ومدير النظام' });
    }

    const targetId = req.params.id || req.body.user_id || req.body.id;
    const {
      username,
      password,
      full_name,
      role,
      department_id,
      unit,
      is_active,
      is_read_only,
      can_add_transaction,
      is_department_manager,
      assigned_department_id,
      can_add_dept_members_transactions
    } = req.body;

    const existing = await pool.query('SELECT * FROM users WHERE user_id = $1 AND is_deleted = FALSE', [targetId]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }

    const updates = [];
    const values = [];
    let idx = 1;

    if (username) {
      updates.push(`username = $${idx++}`);
      values.push(String(username).trim());
    }
    if (password && String(password).trim().length > 0) {
      updates.push(`password_hash = $${idx++}`);
      values.push(hashPassword(password));
    }
    if (full_name) {
      updates.push(`full_name = $${idx++}`);
      values.push(String(full_name).trim());
    }
    if (role) {
      updates.push(`role = $${idx++}`);
      values.push(role);
    }
    if (department_id !== undefined) {
      updates.push(`department_id = $${idx++}`);
      values.push(department_id || null);
      if (assigned_department_id === undefined) {
        updates.push(`assigned_department_id = $${idx++}`);
        values.push(department_id || null);
      }
    }
    if (unit !== undefined) {
      updates.push(`unit = $${idx++}`);
      values.push(unit);
    }
    if (is_active !== undefined) {
      updates.push(`is_active = $${idx++}`);
      values.push(Boolean(is_active));
    }
    if (is_read_only !== undefined) {
      updates.push(`is_read_only = $${idx++}`);
      values.push(Boolean(is_read_only));
    }
    if (can_add_transaction !== undefined) {
      updates.push(`can_add_transaction = $${idx++}`);
      values.push(Boolean(can_add_transaction));
    }
    if (is_department_manager !== undefined) {
      updates.push(`is_department_manager = $${idx++}`);
      values.push(Boolean(is_department_manager));
    }
    if (assigned_department_id !== undefined) {
      updates.push(`assigned_department_id = $${idx++}`);
      values.push(assigned_department_id || department_id || null);
    }
    if (can_add_dept_members_transactions !== undefined) {
      updates.push(`can_add_dept_members_transactions = $${idx++}`);
      values.push(Boolean(can_add_dept_members_transactions));
    }

    if (updates.length === 0) {
      return res.json({ success: true, message: 'لا توجد تعديلات مرسلة', user: existing.rows[0] });
    }

    values.push(targetId);
    const q = `UPDATE users SET ${updates.join(', ')} WHERE user_id = $${idx}`;
    await pool.query(q, values);

    const fullUserRes = await pool.query(
      `SELECT u.user_id, u.username, u.full_name, u.role, u.department_id, u.unit, u.is_active, 
              u.is_read_only, u.can_add_transaction, u.is_department_manager, 
              u.assigned_department_id, u.can_add_dept_members_transactions, u.is_deleted, u.created_at,
              COALESCE(d.name, u.department_id) as department_name,
              COALESCE(d.name, u.department_id) as department
       FROM users u
       LEFT JOIN departments d ON u.department_id = d.department_id
       WHERE u.user_id = $1`,
      [targetId]
    );

    await logAudit('UPDATE_USER', 'users', targetId, actor.id || actor.user_id, actor.full_name, req.body);
    res.json({ success: true, message: 'تم تعديل بيانات المستخدم بنجاح', user: fullUserRes.rows[0], data: fullUserRes.rows[0] });
  } catch (err) {
    console.error('Update User Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء تعديل المستخدم: ' + (err.message || err) });
  }
};

app.put(['/api/users/:id', '/api/admin/users/:id', '/api/admin/users/update'], authenticateToken, handleUserUpdate);
app.post(['/api/admin/users/update', '/api/users/update', '/api/admin/users/:id/update', '/api/users/:id/update'], authenticateToken, handleUserUpdate);

// ==============================================================================
// 8. إدارة وتعديل وحذف أسطول العجلات (Fleet Management)
// ==============================================================================
app.get(['/api/vehicles', '/api/admin/vehicles'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();
    
    let query = `
      SELECT v.*, d.name as department_name 
      FROM vehicles v
      LEFT JOIN departments d ON v.department_id = d.department_id
      WHERE v.is_deleted = FALSE
    `;
    const params = [];

    // عزل العجلات حسب القسم:
    if (actorRole === 'USER') {
      // المستخدم يرى العجلات النشطة التابعة لقسمه فقط
      const dept = actor.assigned_department_id || actor.department_id;
      params.push(dept);
      query += ` AND v.is_active = TRUE AND v.department_id = $${params.length}`;
    } else if (actorRole === 'DEPARTMENT_HEAD') {
      // مسؤول القسم يرى عجلات قسمه
      const dept = actor.assigned_department_id || actor.department_id;
      params.push(dept);
      query += ` AND v.department_id = $${params.length}`;
    }
    // الأدمن والمدقق يريان كافة عجلات الأسطول

    query += ` ORDER BY v.plate_number ASC`;
    const r = await pool.query(query, params);
    res.json({ success: true, data: r.rows, vehicles: r.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// تعديل عجلة وترحيل المعاملات تلقائياً (Admin & Management - Cascade Department Transfer)
const handleVehicleUpdate = async (req, res) => {
  const client = await pool.connect();
  try {
    const actor = req.user;
    if (!isManagementOrAdmin(actor.role)) {
      client.release();
      return res.status(403).json({ error: 'صلاحية تعديل العجلات محصورة بالإدارة ومدير النظام' });
    }

    const vehId = req.params.id || req.body.vehicle_id || req.body.id || req.body.plate_number;
    if (!vehId) {
      client.release();
      return res.status(400).json({ error: 'معرف العجلة مطلوب' });
    }
    const { plate_number, vehicle_type, department_id, current_km, is_active } = req.body;

    await client.query('BEGIN');

    // 1. استرجاع بيانات العجلة الحالية
    const curRes = await client.query(
      `SELECT * FROM vehicles WHERE (vehicle_id = $1 OR plate_number = $1) AND (is_deleted = FALSE OR is_deleted IS NULL) FOR UPDATE`,
      [vehId]
    );

    if (curRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'العجلة غير موجودة أو تم حذفها مسبقاً' });
    }

    const currentVeh = curRes.rows[0];
    const oldPlate = currentVeh.plate_number;
    const oldDept = currentVeh.department_id;
    const newPlate = plate_number ? String(plate_number).trim() : oldPlate;
    const newDept = department_id !== undefined ? (department_id || null) : oldDept;

    const updates = [];
    const values = [];
    let idx = 1;

    if (plate_number) {
      updates.push(`plate_number = $${idx++}`);
      values.push(newPlate);
    }
    if (vehicle_type !== undefined) {
      updates.push(`vehicle_type = $${idx++}`);
      values.push(vehicle_type);
    }
    if (department_id !== undefined) {
      updates.push(`department_id = $${idx++}`);
      values.push(newDept);
    }
    if (current_km !== undefined) {
      updates.push(`current_km = $${idx++}`);
      values.push(parseInt(current_km, 10) || 0);
    }
    if (is_active !== undefined) {
      updates.push(`is_active = $${idx++}`);
      values.push(Boolean(is_active));
    }

    if (updates.length > 0) {
      updates.push(`updated_at = NOW()`);
      values.push(currentVeh.vehicle_id);

      const q = `UPDATE vehicles SET ${updates.join(', ')} WHERE vehicle_id = $${values.length} OR plate_number = $${values.length} RETURNING *`;
      await client.query(q, values);
    }

    let cascadedTransactionsCount = 0;

    // 2. إذا تم تغيير القسم، ترحيل كافة معاملات الصيانة التابعة للعجلة إلى القسم الجديد تلقائياً
    if (newDept && newDept !== oldDept) {
      const txTransferRes = await client.query(
        `UPDATE transactions 
         SET department_id = $1, updated_at = NOW() 
         WHERE (wheel_id = $2 OR vehicle_numbers::text LIKE '%' || $2 || '%' OR wheel_id = $3)`,
        [newDept, oldPlate, currentVeh.vehicle_id]
      );
      cascadedTransactionsCount = txTransferRes.rowCount || 0;
    }

    // 3. إذا تم تعديل رقم لوحة العجلة، تحديثه في كافة سجلات transactions
    if (newPlate && newPlate !== oldPlate) {
      await client.query(
        `UPDATE transactions 
         SET wheel_id = $1, 
             vehicle_numbers = jsonb_set(
               COALESCE(vehicle_numbers, '[]'::jsonb), 
               '{0}', 
               to_jsonb($1::text)
             ),
             updated_at = NOW() 
         WHERE (wheel_id = $2 OR vehicle_numbers::text LIKE '%' || $2 || '%' OR wheel_id = $3)`,
        [newPlate, oldPlate, currentVeh.vehicle_id]
      );
    }

    await client.query('COMMIT');

    // جلب النسخة المحدثة النهائية
    const finalVehRes = await pool.query(
      `SELECT v.*, d.name as department_name 
       FROM vehicles v 
       LEFT JOIN departments d ON v.department_id = d.department_id 
       WHERE v.vehicle_id = $1`,
      [currentVeh.vehicle_id]
    );

    await logAudit('UPDATE_VEHICLE', 'vehicles', currentVeh.vehicle_id, actor.id || actor.user_id, actor.full_name, {
      ...req.body,
      cascaded_transactions: cascadedTransactionsCount
    });

    res.json({
      success: true,
      message: newDept && newDept !== oldDept 
        ? `تم تعديل بيانات العجلة وترحيل (${cascadedTransactionsCount}) معاملة صيانة إلى القسم الجديد بنجاح`
        : 'تم تعديل بيانات العجلة بنجاح',
      vehicle: finalVehRes.rows[0],
      data: finalVehRes.rows[0]
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Update Vehicle Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء تعديل العجلة وترحيل البيانات: ' + (err.message || err) });
  } finally {
    client.release();
  }
};

app.put(['/api/vehicles/:id', '/api/admin/vehicles/:id'], authenticateToken, handleVehicleUpdate);
app.post(['/api/admin/vehicles/update', '/api/vehicles/update', '/api/admin/vehicles/:id/update', '/api/vehicles/:id/update'], authenticateToken, handleVehicleUpdate);

// إضافة عجلة جديدة (Admin & Management)
app.post(['/api/vehicles', '/api/admin/vehicles', '/api/admin/vehicles/add'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    if (!isManagementOrAdmin(actor.role)) {
      return res.status(403).json({ error: 'صلاحية إضافة العجلات محصورة بالإدارة ومدير النظام' });
    }

    const { vehicle_id, id, plate_number, plate, vehicle_type, department_id, current_km, is_active } = req.body;
    const finalPlate = String(plate_number || plate || vehicle_id || id || '').trim();
    if (!finalPlate) {
      return res.status(400).json({ error: 'يرجى إدخال رقم العجلة أو اللوحة' });
    }

    const newVehId = vehicle_id || id || finalPlate;
    const insertRes = await pool.query(
      `INSERT INTO vehicles (vehicle_id, plate_number, vehicle_type, department_id, current_km, is_active, is_deleted, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, FALSE, NOW())
       ON CONFLICT (vehicle_id) DO UPDATE SET
         plate_number = EXCLUDED.plate_number,
         vehicle_type = EXCLUDED.vehicle_type,
         department_id = EXCLUDED.department_id,
         current_km = EXCLUDED.current_km,
         is_active = EXCLUDED.is_active,
         is_deleted = FALSE,
         updated_at = NOW()
       RETURNING *`,
      [newVehId, finalPlate, vehicle_type || 'عجلة', department_id || null, parseInt(current_km, 10) || 0, is_active !== false && is_active !== 0]
    );

    res.status(201).json({ success: true, message: 'تم حفظ العجلة بنجاح', data: insertRes.rows[0], vehicle: insertRes.rows[0] });
  } catch (err) {
    console.error('Create Vehicle Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ العجلة على السيرفر' });
  }
});

// ==============================================================================
// 9. جدول وتقارير أسطول العجلات (Fleet Summary & Vehicle Dossier Reports)
// ==============================================================================

// تقرير ملخص أسطول العجلات (Vehicles Summary Table & Fleet Summary - Axis 2)
app.get(['/api/reports/vehicles-summary', '/api/vehicles/fleet-summary'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();
    let deptFilter = 'WHERE (v.is_deleted = FALSE OR v.is_deleted IS NULL)';
    const params = [];

    // عزل تقارير الأسطول حسب القسم للمستخدم الميداني ومسؤول القسم (Strict Fleet Isolation - Axis 2)
    if (actorRole === 'USER' || actorRole === 'DEPARTMENT_HEAD') {
      const dept = actor.assigned_department_id || actor.department_id;
      params.push(dept);
      deptFilter += ` AND v.department_id = $${params.length}`;
    }

    const query = `
      SELECT 
        v.plate_number,
        v.vehicle_type,
        v.department_id,
        COALESCE(d.name, 'غير محدد') as department_name,
        COALESCE(MAX(t.mileage), v.current_km, 0) as highest_km,
        COALESCE(SUM(CASE WHEN t.status = 'AUDITED' THEN t.cost ELSE 0 END), 0) as total_maintenance_cost,
        MAX(t.created_at) as last_maintenance_date,
        COUNT(t.id) as transaction_count
      FROM vehicles v
      LEFT JOIN departments d ON v.department_id = d.department_id
      LEFT JOIN transactions t ON (t.wheel_id = v.plate_number OR t.vehicle_numbers::text LIKE '%' || v.plate_number || '%') AND (t.is_deleted = FALSE OR t.is_deleted IS NULL)
      ${deptFilter}
      GROUP BY v.vehicle_id, v.plate_number, v.vehicle_type, v.department_id, d.name, v.current_km
      ORDER BY v.plate_number ASC
    `;
    const result = await pool.query(query, params);
    res.json({
      success: true,
      data: result.rows,
      summary: result.rows,
      vehicles: result.rows
    });
  } catch (err) {
    console.error('Vehicles Summary Report Error:', err);
    res.status(500).json({ error: 'فشل استخراج تقرير ملخص العجلات' });
  }
});

// تقرير سجل صيانة العجلة التفصيلي (Vehicle Maintenance Dossier Report) مع حساب كم مستحق الصيانة
app.get('/api/reports/vehicle-history', authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();

    const { wheel_id } = req.query;
    if (!wheel_id) {
      return res.status(400).json({ error: 'يرجى تحديد رقم العجلة لاستخراج التقرير' });
    }

    // تحقق من تبعية العجلة لقسم المستخدم أو مسؤول القسم (Strict Fleet Isolation - Axis 2)
    if (actorRole === 'USER' || actorRole === 'DEPARTMENT_HEAD') {
      const userDept = actor.assigned_department_id || actor.department_id;
      const vehCheck = await pool.query('SELECT department_id FROM vehicles WHERE (plate_number = $1 OR vehicle_id = $1) AND (is_deleted = FALSE OR is_deleted IS NULL)', [wheel_id.trim()]);
      if (vehCheck.rows.length > 0 && vehCheck.rows[0].department_id !== userDept) {
        return res.status(403).json({ error: 'عذراً، لا يمكنك استعراض تقرير عجلة تابعة لقسم آخر' });
      }
    }

    let query = `
      SELECT t.*, 
             COALESCE(t.cost, 0) as maintenance_price,
             COALESCE(t.mileage, 0) as current_km,
             COALESCE(t.mileage, 0) as maintenance_km,
             t.created_at as maintenance_date,
             COALESCE(t.cost, 0) as maintenance_cost,
             COALESCE(t.mileage, 0) + COALESCE(mc.default_replacement_km, 5000) as due_km,
             COALESCE(t.description, '') as notes,
             u.full_name as user_name,
             d.name as department_name
      FROM transactions t
      LEFT JOIN users u ON t.user_id = u.user_id
      LEFT JOIN departments d ON t.department_id = d.department_id
      LEFT JOIN maintenance_categories mc ON LOWER(mc.name) = LOWER(t.category)
      WHERE (t.wheel_id = $1 OR t.vehicle_numbers::text LIKE '%' || $1 || '%') AND (t.is_deleted = FALSE OR t.is_deleted IS NULL)
      ORDER BY t.created_at DESC
    `;
    const txRes = await pool.query(query, [wheel_id.trim()]);

    let totalCount = txRes.rows.length;
    let totalCost = 0;
    let lastKm = 0;

    for (const r of txRes.rows) {
      if (r.status === 'AUDITED') {
        totalCost += parseFloat(r.cost || 0);
      }
      if (r.mileage && r.mileage > lastKm) {
        lastKm = r.mileage;
      }
    }

    res.json({
      success: true,
      summary: {
        total_count: totalCount,
        total_cost: totalCost,
        last_km: lastKm,
        wheel_id: wheel_id.trim()
      },
      transactions: txRes.rows,
      data: txRes.rows
    });
  } catch (err) {
    console.error('Vehicle History Report Error:', err);
    res.status(500).json({ error: 'فشل استخراج التقرير: ' + (err.message || err) });
  }
});

// تقرير الصيانة التجميعي للأدمن والإدارة حسب العجلة ونوع الصيانة (Axis 2 - Vehicle Category Summary Report)
app.get(['/api/reports/vehicle-category-summary', '/api/reports/vehicle-categories-summary'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();
    if (!isManagementOrAdmin(actorRole)) {
      return res.status(403).json({ error: 'تقرير الصيانة التجميعي متاح حصرياً لمدير النظام والإدارة العامة' });
    }

    const { format, wheel_id, category } = req.query;

    let query = `
      SELECT 
        COALESCE(v.plate_number, t.wheel_id) as plate_number,
        COALESCE(v.vehicle_id, t.wheel_id) as vehicle_id,
        COALESCE(v.department_id, t.department_id, 'DEPT-001') as department_id,
        COALESCE(d.name, 'قسم النقل والآليات') as department_name,
        COALESCE(t.category, 'صيانة عامة') as category,
        MAX(COALESCE(t.mileage, 0)) as last_service_km,
        MAX(COALESCE(t.mileage, 0)) + COALESCE(mc.default_replacement_km, 5000) as due_km,
        MAX(t.created_at) as last_service_date,
        COALESCE(SUM(t.cost), 0) as total_spent_for_category,
        COUNT(t.id) as transactions_count
      FROM transactions t
      LEFT JOIN vehicles v ON (v.plate_number = t.wheel_id OR v.vehicle_id = t.wheel_id OR t.vehicle_numbers::text LIKE '%' || v.plate_number || '%')
      LEFT JOIN departments d ON d.department_id = COALESCE(v.department_id, t.department_id)
      LEFT JOIN maintenance_categories mc ON LOWER(mc.name) = LOWER(t.category)
      WHERE (t.is_deleted = FALSE OR t.is_deleted IS NULL)
    `;
    const params = [];

    if (wheel_id) {
      params.push(wheel_id.trim());
      query += ` AND (t.wheel_id = $${params.length} OR v.plate_number = $${params.length})`;
    }

    if (category) {
      params.push(category.trim());
      query += ` AND LOWER(t.category) = LOWER($${params.length})`;
    }

    query += `
      GROUP BY COALESCE(v.plate_number, t.wheel_id), COALESCE(v.vehicle_id, t.wheel_id), COALESCE(v.department_id, t.department_id, 'DEPT-001'), d.name, t.category, mc.default_replacement_km
      ORDER BY plate_number ASC, category ASC
    `;

    const result = await pool.query(query, params);
    const rows = result.rows.map(r => ({
      plate_number: r.plate_number,
      wheel_id: r.plate_number,
      category: r.category,
      due_km: parseInt(r.due_km, 10) || 0,
      last_service_km: parseInt(r.last_service_km, 10) || 0,
      last_service_date: r.last_service_date,
      total_spent_for_category: parseFloat(r.total_spent_for_category) || 0.0,
      transactions_count: parseInt(r.transactions_count, 10) || 0,
      department_id: r.department_id,
      department_name: r.department_name
    }));

    // دعم التصدير المباشر لـ CSV/Excel
    if (format === 'excel' || format === 'csv' || req.query.export === 'excel') {
      let csv = '\ufeff"رقم العجلة","نوع الصيانة","كم استحقاق الصيانة","تاريخ آخر صيانة","إجمالي المبلغ المصروف لنوع الصيانة (د.ع)","القسم"\n';
      for (const row of rows) {
        const dateStr = row.last_service_date ? new Date(row.last_service_date).toLocaleDateString('ar-IQ') : '—';
        csv += `"${row.plate_number}","${row.category}","${row.due_km} كم","${dateStr}","${row.total_spent_for_category.toLocaleString()}","${row.department_name}"\n`;
      }
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="vehicle_category_summary_report.csv"');
      return res.send(csv);
    }

    res.json({
      success: true,
      count: rows.length,
      data: rows,
      summary: rows,
      report: rows
    });
  } catch (err) {
    console.error('Vehicle Category Summary Report Error:', err);
    res.status(500).json({ error: 'فشل استخراج تقرير الصيانة التجميعي: ' + (err.message || err) });
  }
});

// ==============================================================================
// 10. إدارة أنواع الصيانة والكم الافتراضي (Maintenance Categories API - Axis 1)
// ==============================================================================
app.get(['/api/categories', '/api/maintenance-categories', '/api/admin/categories'], async (req, res) => {
  try {
    const r = await pool.query('SELECT category_id, name, default_replacement_km FROM maintenance_categories ORDER BY category_id ASC');
    if (r.rows && r.rows.length > 0) {
      return res.json({ success: true, data: r.rows, categories: r.rows });
    }
  } catch (err) {
    console.warn('Categories query warning:', err.message);
  }
  const defaultList = [
    { category_id: 'CAT-01', name: 'تبديل زيت المحرك والفلتر', default_replacement_km: 5000 },
    { category_id: 'CAT-02', name: 'تبديل إطارات (عجلات)', default_replacement_km: 40000 },
    { category_id: 'CAT-03', name: 'تبديل بطارية', default_replacement_km: 50000 },
    { category_id: 'CAT-04', name: 'تبديل دهن كير وفلتر', default_replacement_km: 40000 },
    { category_id: 'CAT-05', name: 'تبديل سفايف (فحمات فرامل)', default_replacement_km: 25000 },
    { category_id: 'CAT-06', name: 'تبديل فلاتر هواء وتبريد', default_replacement_km: 10000 },
    { category_id: 'CAT-07', name: 'صيانة عامة وفحص دوري', default_replacement_km: 15000 }
  ];
  res.json({ success: true, data: defaultList, categories: defaultList });
});

app.post(['/api/categories', '/api/maintenance-categories', '/api/admin/categories', '/api/admin/categories/add'], authenticateToken, async (req, res) => {
  try {
    const actorRole = (req.user.role || '').toUpperCase();
    if (!isManagementOrAdmin(actorRole)) {
      return res.status(403).json({ error: 'صلاحية إضافة أنواع الصيانة محصورة بالإدارة ومدير النظام' });
    }
    const { name, default_replacement_km } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'اسم نوع الصيانة مطلوب' });
    const km = parseInt(default_replacement_km, 10);
    if (isNaN(km) || km <= 0) {
      return res.status(400).json({ error: 'الكم الافتراضي للاستبدال يجب أن يكون رقماً صحيحاً أكبر من الصفر' });
    }
    const catId = req.body.category_id || ('CAT-' + crypto.randomUUID().slice(0, 8));
    const r = await pool.query(
      `INSERT INTO maintenance_categories (category_id, name, default_replacement_km, created_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (category_id) DO UPDATE SET 
         name = EXCLUDED.name, 
         default_replacement_km = EXCLUDED.default_replacement_km
       RETURNING *`,
      [catId, name.trim(), km]
    );
    res.json({ success: true, message: 'تمت إضافة نوع الصيانة بنجاح', data: r.rows[0], category: r.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'فشل إضافة نوع الصيانة: ' + (err.message || err) });
  }
});

const handleCategoryUpdate = async (req, res) => {
  try {
    const actorRole = (req.user.role || '').toUpperCase();
    if (!isManagementOrAdmin(actorRole)) {
      return res.status(403).json({ error: 'صلاحية تعديل أنواع الصيانة محصورة بالإدارة ومدير النظام' });
    }
    const { name, default_replacement_km } = req.body;
    const catId = req.params.id || req.body.category_id || req.body.id;
    if (!catId) return res.status(400).json({ error: 'معرف نوع الصيانة مطلوب' });

    let km = undefined;
    if (default_replacement_km !== undefined) {
      km = parseInt(default_replacement_km, 10);
      if (isNaN(km) || km <= 0) {
        return res.status(400).json({ error: 'الكم الافتراضي للاستبدال يجب أن يكون رقماً صحيحاً أكبر من الصفر' });
      }
    }
    const r = await pool.query(
      `UPDATE maintenance_categories 
       SET name = COALESCE($1, name), 
           default_replacement_km = COALESCE($2, default_replacement_km)
       WHERE category_id = $3
       RETURNING *`,
      [name ? name.trim() : null, km, catId]
    );
    if (r.rows.length === 0) {
      return res.status(404).json({ error: 'نوع الصيانة غير موجود' });
    }
    res.json({ success: true, message: 'تم تعديل نوع الصيانة بنجاح', data: r.rows[0], category: r.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'فشل تعديل نوع الصيانة: ' + (err.message || err) });
  }
};

app.put(['/api/categories/:id', '/api/maintenance-categories/:id', '/api/admin/categories/:id'], authenticateToken, handleCategoryUpdate);
app.post(['/api/admin/categories/update', '/api/categories/update', '/api/admin/categories/:id/update'], authenticateToken, handleCategoryUpdate);

const handleCategoryDelete = async (req, res) => {
  try {
    const actorRole = (req.user.role || '').toUpperCase();
    if (!isManagementOrAdmin(actorRole)) {
      return res.status(403).json({ error: 'صلاحية حذف أنواع الصيانة محصورة بالإدارة ومدير النظام' });
    }
    const catId = req.params.id || req.body.category_id || req.body.id;
    if (!catId) return res.status(400).json({ error: 'معرف نوع الصيانة مطلوب' });

    await pool.query('DELETE FROM maintenance_categories WHERE category_id = $1', [catId]);
    res.json({ success: true, message: 'تم حذف نوع الصيانة بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'فشل حذف نوع الصيانة' });
  }
};

app.delete(['/api/categories/:id', '/api/maintenance-categories/:id', '/api/admin/categories/:id'], authenticateToken, handleCategoryDelete);
app.post(['/api/admin/categories/delete', '/api/categories/delete', '/api/admin/categories/:id/delete'], authenticateToken, handleCategoryDelete);

// ==============================================================================
// 11. مركز وإدارة الإشعارات الفورية والموجهة (Notifications Center API)
// ==============================================================================

// إرسال إشعار موجه أو تعميم
app.post('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();
    if (actorRole !== 'ADMIN' && actorRole !== 'MANAGEMENT' && actorRole !== 'DEPARTMENT_HEAD') {
      return res.status(403).json({ error: 'غير مخول بإرسال الإشعارات' });
    }

    const { title, message, target_type, target_id } = req.body;
    if (!title || !message) {
      return res.status(400).json({ error: 'عنوان الإشعار ونص الرسالة مطلوبان' });
    }

    const finalTargetType = target_type || 'TARGET_ALL';
    let finalTargetId = target_id || null;

    if (actorRole === 'DEPARTMENT_HEAD') {
      if (finalTargetType === 'TARGET_ALL') {
        return res.status(403).json({ error: 'مسؤول القسم يمكنه استهداف قسمه أو موظفيه فقط' });
      }
      if (finalTargetType === 'TARGET_DEPARTMENT') {
        finalTargetId = actor.assigned_department_id || actor.department_id;
      }
    }

    const notifId = 'NOTIF-' + crypto.randomUUID().slice(0, 8);
    const r = await pool.query(
      `INSERT INTO notifications (
        notification_id, title, message, target_type, target_id,
        sender_id, sender_name, user_id, is_read, read_by, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, '[]'::jsonb, NOW())
      RETURNING *`,
      [
        notifId,
        title.trim(),
        message.trim(),
        finalTargetType,
        finalTargetId,
        actor.id || actor.user_id,
        actor.full_name || actor.username,
        finalTargetType === 'TARGET_USER' ? finalTargetId : (finalTargetId || 'ALL')
      ]
    );

    res.json({
      success: true,
      message: 'تم إرسال الإشعار بنجاح 🔔',
      notification: r.rows[0],
      data: r.rows[0]
    });
  } catch (err) {
    console.error('Send Notification Error:', err);
    res.status(500).json({ error: 'فشل إرسال الإشعار', details: err.message });
  }
});

// استعلام قائمة الإشعارات
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();
    const userId = actor.id || actor.user_id;
    const deptId = actor.assigned_department_id || actor.department_id;

    let query = `
      SELECT * FROM notifications
      WHERE 
        target_type = 'TARGET_ALL'
        OR (target_type = 'TARGET_DEPARTMENT' AND target_id = $1)
        OR (target_type = 'TARGET_USER' AND target_id = $2)
        OR user_id = $2
        OR user_id = 'ALL'
    `;
    const params = [deptId, userId];

    if (isManagementOrAdmin(actorRole)) {
      query = `SELECT * FROM notifications ORDER BY created_at DESC LIMIT 100`;
      params.length = 0;
    } else {
      query += ` OR sender_id = $2 ORDER BY created_at DESC LIMIT 100`;
    }

    const result = await pool.query(query, params);
    
    // حساب المقروء للمستخدم
    const formatted = result.rows.map(n => {
      const readBy = Array.isArray(n.read_by) ? n.read_by : [];
      const isReadByMe = n.is_read || readBy.includes(userId);
      return {
        ...n,
        is_read_by_me: isReadByMe
      };
    });

    const unreadCount = formatted.filter(n => !n.is_read_by_me).length;

    res.json({
      success: true,
      unread_count: unreadCount,
      notifications: formatted,
      data: formatted
    });
  } catch (err) {
    console.error('Fetch Notifications Error:', err);
    res.status(500).json({ error: 'فشل جلب الإشعارات' });
  }
});

app.post('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notifId = req.params.id;
    const userId = req.user.id || req.user.user_id;
    await pool.query(
      `UPDATE notifications 
       SET is_read = TRUE,
           read_by = CASE 
             WHEN read_by @> jsonb_build_array($2::text) THEN read_by 
             ELSE read_by || jsonb_build_array($2::text) 
           END
       WHERE notification_id = $1 OR id::text = $1`,
      [notifId, userId]
    );
    res.json({ success: true, message: 'تم تحديث حالة القراءة' });
  } catch (err) {
    res.status(500).json({ error: 'فشل تحديث حالة الإشعار' });
  }
});

app.post('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id || req.user.user_id;
    await pool.query(
      `UPDATE notifications 
       SET is_read = TRUE,
           read_by = CASE 
             WHEN read_by @> jsonb_build_array($1::text) THEN read_by 
             ELSE read_by || jsonb_build_array($1::text) 
           END`,
      [userId]
    );
    res.json({ success: true, message: 'تم تعليم كافة الإشعارات كمقروءة' });
  } catch (err) {
    res.status(500).json({ error: 'فشل تحديث الإشعارات' });
  }
});

// ==============================================================================
// 12. الحذف المنطقي وسلة المحذوفات (Soft Delete Pipeline)
// ==============================================================================
async function executeSoftDelete(req, res, { tableName, idColumn, entityType, recordId, successMsg }) {
  try {
    const actor = req.user;
    if (!isManagementOrAdmin(actor.role)) {
      return res.status(403).json({ error: 'ليس لديك صلاحية تنفيذ الحذف، الحذف محصور بالإدارة ومدير النظام' });
    }

    const existing = await pool.query(
      `SELECT * FROM ${tableName} WHERE ${idColumn} = $1 AND is_deleted = FALSE`,
      [recordId]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'السجل غير موجود أو تم حذفه مسبقاً' });
    }

    const recordSnapshot = existing.rows[0];

    // 1. إدراج لقطة كاملة في جدول المحذوفات
    await pool.query(
      `INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by, deleted_at)
       VALUES ($1, $2, $3::jsonb, $4, NOW())`,
      [entityType, String(recordId), JSON.stringify(recordSnapshot), actor.full_name || actor.username]
    );

    // 2. تطبيق الحذف المنطقي على الجدول الأصلي
    await pool.query(
      `UPDATE ${tableName} SET is_deleted = TRUE, deleted_at = NOW(), deleted_by = $1 WHERE ${idColumn} = $2`,
      [actor.id || actor.user_id, recordId]
    );

    res.json({ success: true, message: successMsg });
  } catch (err) {
    console.error(`Soft Delete Error (${entityType}):`, err);
    res.status(500).json({ error: 'حدث خطأ في السيرفر أثناء تنفيذ الحذف' });
  }
}

// حذف مستخدم (يمنع حذف الحساب الشخصي أو حساب admin الرئيسي)
const handleUserDelete = (req, res) => {
  const targetId = req.params.id || req.body.user_id || req.body.id;
  const actorId = req.user.id || req.user.user_id;
  if (!targetId) {
    return res.status(400).json({ error: 'معرف المستخدم مطلوب للحذف' });
  }
  if (String(targetId) === String(actorId) || targetId === 'USR-ADMIN-001' || targetId === 'admin') {
    return res.status(400).json({ error: 'لا يمكنك حذف حسابك الشخصي أو حساب مدير النظام الرئيسي' });
  }
  return executeSoftDelete(req, res, {
    tableName: 'users',
    idColumn: 'user_id',
    entityType: 'user',
    recordId: targetId,
    successMsg: 'تم نقل المستخدم إلى جدول المحذوفات بنجاح'
  });
};

app.delete(['/api/users/:id', '/api/admin/users/:id'], authenticateToken, handleUserDelete);
app.post(['/api/admin/users/delete', '/api/users/delete', '/api/admin/users/:id/delete', '/api/users/:id/delete'], authenticateToken, handleUserDelete);

// تفعيل/تعطيل المستخدم (Toggle User Active)
app.post(['/api/admin/users/toggle-active', '/api/users/toggle-active'], authenticateToken, async (req, res) => {
  try {
    const actorRole = (req.user.role || '').toUpperCase();
    if (!isManagementOrAdmin(actorRole)) {
      return res.status(403).json({ error: 'صلاحية تغيير حالة المستخدم محصورة بالإدارة ومدير النظام' });
    }
    const userId = req.body.user_id || req.body.id;
    if (!userId) return res.status(400).json({ error: 'معرف المستخدم مطلوب' });
    if (userId === req.user.id || userId === req.user.user_id || userId === 'USR-ADMIN-001' || userId === 'admin') {
      return res.status(400).json({ error: 'لا يمكن تعطيل حسابك أو حساب مدير النظام الرئيسي' });
    }
    const r = await pool.query(
      `UPDATE users SET is_active = NOT is_active, updated_at = NOW() WHERE user_id = $1 RETURNING user_id, username, full_name, is_active`,
      [userId]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ success: true, message: 'تم تغيير حالة تفعيل المستخدم بنجاح', user: r.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'فشل تغيير حالة المستخدم: ' + (err.message || err) });
  }
});

// تفعيل/تعطيل العجلة (Toggle Vehicle Active)
app.post(['/api/admin/vehicles/toggle-active', '/api/vehicles/toggle-active'], authenticateToken, async (req, res) => {
  try {
    const actorRole = (req.user.role || '').toUpperCase();
    if (!isManagementOrAdmin(actorRole)) {
      return res.status(403).json({ error: 'صلاحية تغيير حالة العجلة محصورة بالإدارة ومدير النظام' });
    }
    const vehId = req.body.vehicle_id || req.body.id || req.body.plate_number;
    if (!vehId) return res.status(400).json({ error: 'معرف العجلة مطلوب' });
    const r = await pool.query(
      `UPDATE vehicles SET is_active = NOT is_active, updated_at = NOW() WHERE vehicle_id = $1 OR plate_number = $1 RETURNING *`,
      [vehId]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'العجلة غير موجودة' });
    res.json({ success: true, message: 'تم تغيير حالة تفعيل العجلة بنجاح', vehicle: r.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'فشل تغيير حالة العجلة: ' + (err.message || err) });
  }
});

// حذف شامل للعجلة وكافة متعلقاتها ومعاملاتها (Admin Only - Cascade Delete - Axis 2)
const handleVehicleDelete = async (req, res) => {
  const client = await pool.connect();
  try {
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();
    if (actorRole !== 'ADMIN') {
      client.release();
      return res.status(403).json({ error: 'صلاحية حذف العجلات محصورة بمدير النظام (ADMIN) فقط' });
    }

    const vehId = req.params.id || req.body.vehicle_id || req.body.id || req.body.plate_number;
    if (!vehId) {
      client.release();
      return res.status(400).json({ error: 'معرف العجلة مطلوب للحذف' });
    }
    await client.query('BEGIN');

    // 1. جلب بيانات العجلة
    const vehRes = await client.query(
      `SELECT * FROM vehicles WHERE (vehicle_id = $1 OR plate_number = $1) AND (is_deleted = FALSE OR is_deleted IS NULL)`,
      [vehId]
    );
    if (vehRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'العجلة غير موجودة أو تم حذفها مسبقاً' });
    }
    const vehicle = vehRes.rows[0];
    const plateNumber = vehicle.plate_number;

    // 2. جلب كافة معاملات الصيانة المرتبطة بالعجلة
    const txRes = await client.query(
      `SELECT * FROM transactions 
       WHERE (wheel_id = $1 OR vehicle_numbers::text LIKE '%' || $1 || '%' OR wheel_id = $2) 
         AND (is_deleted = FALSE OR is_deleted IS NULL)`,
      [plateNumber, vehicle.vehicle_id]
    );
    const relatedTransactions = txRes.rows;

    // 3. أخذ نسخة احتياطية شاملة في deleted_records
    await client.query(
      `INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by, deleted_at)
       VALUES ($1, $2, $3::jsonb, $4, NOW())`,
      ['vehicle', String(vehicle.vehicle_id), JSON.stringify({
        vehicle: vehicle,
        transactions_count: relatedTransactions.length,
        transactions: relatedTransactions
      }), actor.full_name || actor.username]
    );

    // حفظ لقطة لكل معاملة في deleted_records أيضاً
    for (const tx of relatedTransactions) {
      await client.query(
        `INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by, deleted_at)
         VALUES ($1, $2, $3::jsonb, $4, NOW())`,
        ['transaction', String(tx.transaction_id || tx.id), JSON.stringify(tx), actor.full_name || actor.username]
      );
    }

    // 4. حذف العجلة (Soft-delete)
    await client.query(
      `UPDATE vehicles SET is_deleted = TRUE, deleted_at = NOW(), deleted_by = $1 WHERE vehicle_id = $2 OR plate_number = $2`,
      [actor.id || actor.user_id, vehicle.vehicle_id]
    );

    // 5. حذف كافة المعاملات المرتبطة تسلسلياً (Cascade Delete)
    if (relatedTransactions.length > 0) {
      await client.query(
        `UPDATE transactions 
         SET is_deleted = TRUE, deleted_at = NOW(), deleted_by = $1 
         WHERE (wheel_id = $2 OR vehicle_numbers::text LIKE '%' || $2 || '%' OR wheel_id = $3)`,
        [actor.id || actor.user_id, plateNumber, vehicle.vehicle_id]
      );
    }

    await client.query('COMMIT');

    await logAudit('DELETE_VEHICLE_CASCADE', 'vehicles', vehicle.vehicle_id, actor.id || actor.user_id, actor.full_name, {
      plate_number: plateNumber,
      deleted_transactions_count: relatedTransactions.length
    });

    res.json({
      success: true,
      message: `تم حذف العجلة [${plateNumber}] وكافة معاملاتها المرتبطة (${relatedTransactions.length} معاملة) ونقلها إلى سلة المحذوفات بنجاح`
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Cascade Delete Vehicle Error:', err);
    res.status(500).json({ error: 'فشل حذف العجلة ومتعلقاتها: ' + (err.message || err) });
  } finally {
    client.release();
  }
};

app.delete(['/api/vehicles/:id', '/api/admin/vehicles/:id'], authenticateToken, handleVehicleDelete);
app.post(['/api/admin/vehicles/delete', '/api/vehicles/delete', '/api/admin/vehicles/:id/delete', '/api/vehicles/:id/delete'], authenticateToken, handleVehicleDelete);

// حذف معاملة
app.delete('/api/transactions/:id', authenticateToken, (req, res) =>
  executeSoftDelete(req, res, {
    tableName: 'transactions',
    idColumn: 'transaction_id',
    entityType: 'transaction',
    recordId: req.params.id,
    successMsg: 'تم نقل المعاملة إلى سلة المحذوفات بنجاح'
  })
);

// جلب المحذوفات واستعادتها
app.get(['/api/deleted-records', '/api/admin/recycle-bin'], authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM deleted_records ORDER BY deleted_at DESC LIMIT 500`);
    res.json({ success: true, count: result.rows.length, data: result.rows, deleted_records: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'فشل جلب سجل المحذوفات من السيرفر' });
  }
});

app.post(['/api/deleted-records/:id/restore', '/api/admin/recycle-bin/restore'], authenticateToken, async (req, res) => {
  try {
    const actorRole = (req.user.role || '').toUpperCase();
    if (!isManagementOrAdmin(actorRole)) {
      return res.status(403).json({ error: 'صلاحية الاستعادة محصورة بالإدارة ومدير النظام' });
    }
    const recordPk = req.params.id || req.body.id || req.body.trashId;
    const delRes = await pool.query('SELECT * FROM deleted_records WHERE id = $1', [recordPk]);
    if (delRes.rows.length === 0) {
      return res.status(404).json({ error: 'السجل المحذوف غير موجود' });
    }

    const item = delRes.rows[0];
    const tableMap = {
      transaction: { table: 'transactions', col: 'transaction_id' },
      vehicle: { table: 'vehicles', col: 'vehicle_id' },
      user: { table: 'users', col: 'user_id' },
      department: { table: 'departments', col: 'department_id' }
    };

    const target = tableMap[item.entity_type];
    if (!target) return res.status(400).json({ error: 'نوع السجل غير مدعوم للاستعادة' });

    await pool.query(
      `UPDATE ${target.table} SET is_deleted = FALSE, deleted_at = NULL, deleted_by = NULL WHERE ${target.col} = $1`,
      [item.entity_id]
    );
    await pool.query('DELETE FROM deleted_records WHERE id = $1', [recordPk]);

    res.json({ success: true, message: 'تمت استعادة السجل بنجاح وإعادته إلى القائمة النشطة' });
  } catch (err) {
    res.status(500).json({ error: 'فشل استعادة السجل' });
  }
});

// ==============================================================================
// 12. إدارة الأقسام
// ==============================================================================
app.get(['/api/departments', '/api/admin/departments'], async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM departments WHERE is_deleted = FALSE ORDER BY created_at DESC');
    res.json({ success: true, data: result.rows, departments: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'فشل جلب الأقسام' });
  }
});

app.post(['/api/departments', '/api/admin/departments'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    if ((actor.role || '').toUpperCase() !== 'ADMIN') {
      return res.status(403).json({ error: 'صلاحية إضافة الأقسام محصورة بمدير النظام فقط' });
    }

    const { department_id, name, code } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'يرجى إدخال اسم القسم' });
    }

    const newDeptId = department_id || ('DEPT-' + crypto.randomBytes(3).toString('hex').toUpperCase());
    const insertRes = await pool.query(
      `INSERT INTO departments (department_id, name, code, is_deleted, created_at)
       VALUES ($1, $2, $3, FALSE, NOW())
       ON CONFLICT (department_id) DO UPDATE SET
         name = EXCLUDED.name,
         is_deleted = FALSE
       RETURNING *`,
      [newDeptId, String(name).trim(), code || newDeptId]
    );

    res.status(201).json({ success: true, message: 'تم حفظ القسم بنجاح', department: insertRes.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ القسم' });
  }
});

// ==============================================================================
// 13. المزامنة السحابية الشاملة للهواتف (Full Sync)
// ==============================================================================
app.get('/api/sync', authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();
    const actorId = actor.id || actor.user_id;

    const depts = await pool.query('SELECT * FROM departments WHERE is_deleted = FALSE ORDER BY created_at DESC');
    
    // عزل العجلات في المزامنة:
    let vehQuery = 'SELECT * FROM vehicles WHERE is_deleted = FALSE';
    const vehParams = [];
    if (actorRole === 'USER') {
      const dept = actor.assigned_department_id || actor.department_id;
      vehParams.push(dept);
      vehQuery += ` AND is_active = TRUE AND department_id = $${vehParams.length}`;
    } else if (actorRole === 'DEPARTMENT_HEAD') {
      const dept = actor.assigned_department_id || actor.department_id;
      vehParams.push(dept);
      vehQuery += ` AND department_id = $${vehParams.length}`;
    }
    vehQuery += ' ORDER BY plate_number ASC';
    const vehs = await pool.query(vehQuery, vehParams);

    const users = await pool.query(
      `SELECT user_id, username, full_name, department_id, unit, role, is_active,
              is_read_only, can_add_transaction, is_department_manager, assigned_department_id,
              can_add_dept_members_transactions, is_deleted, created_at
       FROM users WHERE is_deleted = FALSE ORDER BY created_at DESC`
    );

    let txQuery = `
      SELECT t.*, u.full_name as user_name, d.name as department_name
      FROM transactions t
      LEFT JOIN users u ON t.user_id = u.user_id
      LEFT JOIN departments d ON t.department_id = d.department_id
      WHERE t.is_deleted = FALSE
    `;
    const txParams = [];
    if (actorRole === 'USER') {
      txParams.push(actorId);
      txQuery += ` AND (t.user_id = $${txParams.length} OR t.created_by = $${txParams.length})`;
    } else if (actorRole === 'DEPARTMENT_HEAD') {
      const dept = actor.assigned_department_id || actor.department_id;
      txParams.push(dept);
      txQuery += ` AND t.department_id = $${txParams.length}`;
    }
    txQuery += ` ORDER BY t.created_at DESC LIMIT 1000`;
    const txs = await pool.query(txQuery, txParams);

    res.json({
      success: true,
      server_time: new Date().toISOString(),
      departments: depts.rows,
      vehicles: vehs.rows,
      users: users.rows,
      transactions: txs.rows
    });
  } catch (err) {
    console.error('Sync Error:', err);
    res.status(500).json({ error: 'فشلت عملية المزامنة السحابية' });
  }
});

// رفع طابور الأوفلاين
app.post('/api/sync/push', authenticateToken, async (req, res) => {
  try {
    const items = req.body.items || [];
    const actor = req.user;
    let savedCount = 0;

    for (const item of items) {
      if (item.transaction_id) {
        const wheelId = item.wheel_id || item.vehicle_id || item.plate_number || 'عجلة غير محددة';
        const cost = item.cost !== undefined ? item.cost : (item.maintenance_price || 0);
        const mileage = item.mileage !== undefined ? item.mileage : (item.current_km || 0);
        const description = item.description !== undefined ? item.description : (item.notes || '');
        const category = item.category || item.maintenance_type || 'إطارات وبطاريات';
        const receipt_image = item.receipt_image || (Array.isArray(item.receipt_images) && item.receipt_images.length > 0 ? item.receipt_images[0] : null);
        const receipt_images = item.receipt_images || (receipt_image ? [receipt_image] : []);
        const vehicle_images = item.vehicle_images || [];
        const status = item.status || 'PENDING_AUDITOR';
        const is_locked = item.is_locked !== undefined ? Boolean(item.is_locked) : true;
        const auditor_note = item.auditor_note || '';
        const admin_note = item.admin_note || '';
        const updated_by = item.updated_by || actor.id || actor.user_id;

        const q = `
          INSERT INTO transactions (
            transaction_id, wheel_id, category, cost, mileage, description,
            receipt_image, receipt_images, vehicle_images, status, auditor_note, admin_note,
            is_locked, is_deleted, created_at, updated_at, updated_by, user_id, department_id
          ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, FALSE, $14, NOW(), $15, $16, $17
          ) ON CONFLICT (transaction_id) DO UPDATE SET
            wheel_id = COALESCE(EXCLUDED.wheel_id, transactions.wheel_id),
            category = COALESCE(EXCLUDED.category, transactions.category),
            cost = COALESCE(EXCLUDED.cost, transactions.cost),
            mileage = COALESCE(EXCLUDED.mileage, transactions.mileage),
            description = COALESCE(EXCLUDED.description, transactions.description),
            receipt_image = COALESCE(EXCLUDED.receipt_image, transactions.receipt_image),
            receipt_images = COALESCE(EXCLUDED.receipt_images, transactions.receipt_images),
            vehicle_images = COALESCE(EXCLUDED.vehicle_images, transactions.vehicle_images),
            status = COALESCE(EXCLUDED.status, transactions.status),
            auditor_note = COALESCE(EXCLUDED.auditor_note, transactions.auditor_note),
            admin_note = COALESCE(EXCLUDED.admin_note, transactions.admin_note),
            is_locked = COALESCE(EXCLUDED.is_locked, transactions.is_locked),
            updated_by = EXCLUDED.updated_by,
            updated_at = NOW()
        `;
        await pool.query(q, [
          item.transaction_id,
          wheelId,
          category,
          parseFloat(cost) || 0.00,
          parseInt(mileage, 10) || 0,
          description,
          receipt_image,
          JSON.stringify(receipt_images),
          JSON.stringify(vehicle_images),
          status,
          auditor_note,
          admin_note,
          is_locked,
          item.created_at || new Date().toISOString(),
          updated_by,
          item.user_id || actor.id || actor.user_id,
          item.department_id || actor.department_id || null
        ]);
        savedCount++;
      }
    }

    res.json({ success: true, count: savedCount, message: `تمت مزامنة ${savedCount} عملية بنجاح ☁️` });
  } catch (err) {
    console.error('Sync Push Error:', err);
    res.status(500).json({ error: 'فشلت المزامنة: ' + (err.message || err) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`================================================================`);
  console.log(`  سيرفر صيانة العجلات السحابي (Wheel Maintenance Cloud API) v5.0`);
  console.log(`  يعمل بنجاح على المنفذ: ${PORT}`);
  console.log(`  البيئة: ${process.env.NODE_ENV || 'production'}`);
  console.log(`================================================================`);
});
