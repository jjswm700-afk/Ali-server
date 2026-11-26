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

// التحقق من وجود الجداول الأساسية والفهارس عند الإقلاع
async function ensureTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        notification_id TEXT UNIQUE NOT NULL,
        user_id TEXT NOT NULL,
        transaction_id TEXT,
        title TEXT NOT NULL,
        purpose TEXT DEFAULT 'إشعار',
        message TEXT NOT NULL,
        type TEXT DEFAULT 'INFO',
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read);
    `);
    console.log('✅ Database schema verified (notifications table ready)');
  } catch (err) {
    console.warn('DB Init Note:', err.message);
  }
}
ensureTables();

// وسيط التحقق الأمني من الرمز المميز (JWT Authentication Middleware) مع دعم x-user-id للتطوير
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
      if (err) {
        return res.status(403).json({ error: 'انتهت صلاحية الجلسة أو الرمز غير صالح، يرجى تسجيل الدخول مجدداً' });
      }
      req.user = decodedUser;
      next();
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

// دالة إرسال إشعار لمستخدم
async function sendNotification(userId, txId, title, purpose, message, type = 'INFO') {
  try {
    const notifId = 'NOTIF-' + crypto.randomUUID().slice(0, 8);
    await pool.query(
      `INSERT INTO notifications (notification_id, user_id, transaction_id, title, purpose, message, type, is_read, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, NOW())`,
      [notifId, userId, txId, title, purpose, message, type]
    );
  } catch (e) {
    console.warn('Send Notification Warning:', e.message);
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
    version: '5.0.0 (Enterprise RBAC & Workflow)',
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
      SELECT u.*, d.name as department_name 
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
              d.name as department_name
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

    // حظر الإنشاء من المدقق أو الأدمن (المعاملات تُنشأ حصراً من قبل USER أو DEPARTMENT_HEAD)
    const normalizedRole = (user.role || '').toUpperCase();
    if (normalizedRole === 'AUDITOR' || normalizedRole === 'ADMIN') {
      return res.status(403).json({ 
        error: 'عذراً، لا يمكن للمدقق أو مدير النظام إنشاء معاملات صيانة؛ الإنشاء مخصص للمستخدمين الميدانيين ومسؤولي الأقسام فقط.' 
      });
    }

    if (user.is_read_only) {
      return res.status(403).json({ error: 'حسابك مخصص للقراءة والاطلاع فقط، لا تملك صلاحية إضافة معاملات.' });
    }

    // استنتاج القسم تلقائياً من المستخدم
    const userDept = user.assigned_department_id || user.department_id || req.body.department_id;
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

    // التحقق من أن العجلة تابعة لقسم المستخدم (منع الإضافة العشوائية أو التعدي على أقسام أخرى)
    const vehCheck = await pool.query(
      `SELECT * FROM vehicles WHERE (vehicle_id = $1 OR plate_number = $1) AND is_deleted = FALSE`,
      [wheelId]
    );

    if (vehCheck.rows.length > 0) {
      const existingVeh = vehCheck.rows[0];
      if (existingVeh.department_id && existingVeh.department_id !== userDept && normalizedRole !== 'ADMIN') {
        return res.status(403).json({ 
          error: `العجلة (${wheelId}) تابعة لقسم آخر، ولا يمكنك إنشاء معاملة لعجلات خارج قسمك.` 
        });
      }
    } else {
      // تسجيل العجلة تلقائياً تحت قسم المستخدم
      await pool.query(
        `INSERT INTO vehicles (vehicle_id, plate_number, vehicle_type, department_id, current_km, is_active, is_deleted, created_at)
         VALUES ($1, $1, 'عجلة', $2, $3, TRUE, FALSE, NOW())
         ON CONFLICT (vehicle_id) DO NOTHING`,
        [wheelId, userDept, parseInt(req.body.mileage || req.body.current_km, 10) || 0]
      );
    }

    const mileage = parseInt(req.body.mileage !== undefined ? req.body.mileage : (req.body.current_km || 0), 10) || 0;
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
             COALESCE(t.description, '') as notes,
             u.full_name as user_name, 
             u.username,
             d.name as department_name,
             c.full_name as created_by_name
      FROM transactions t
      LEFT JOIN users u ON t.user_id = u.user_id
      LEFT JOIN departments d ON t.department_id = d.department_id
      LEFT JOIN users c ON t.created_by = c.user_id
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

    if (actorRole !== 'AUDITOR' && actorRole !== 'ADMIN') {
      return res.status(403).json({ error: 'عذراً، صلاحية تدقيق الوصولات مخصصة لحساب المدقق فقط.' });
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

      // إشعار لمديري النظام (Admins)
      const admins = await pool.query(`SELECT user_id FROM users WHERE UPPER(role) = 'ADMIN' AND is_active = TRUE AND is_deleted = FALSE`);
      for (const adm of admins.rows) {
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
// 6. مسار الاعتماد المالي والإداري من الإدارة (Phase 3: Admin Final Approval)
// ==============================================================================
app.post(['/api/admin/transactions/:id/review', '/api/transactions/:id/approve', '/api/admin/transactions/:id/status'], authenticateToken, async (req, res) => {
  try {
    const txId = req.params.id;
    const { action, cost, maintenance_price, admin_note, note } = req.body;
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();

    if (actorRole !== 'ADMIN') {
      return res.status(403).json({ error: 'عذراً، صلاحية الاعتماد المالي وتحديد المبلغ والاعتماد النهائي محصورة بمدير النظام (ADMIN) فقط.' });
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
// 7. إدارة وتحديث وحذف المستخدمين (Users Management - Admin Only)
// ==============================================================================
app.get(['/api/users', '/api/admin/users'], authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.user_id, u.username, u.full_name, u.role, u.department_id, u.unit, u.is_active, 
              u.is_read_only, u.can_add_transaction, u.is_department_manager, 
              u.assigned_department_id, u.can_add_dept_members_transactions, u.is_deleted, u.created_at,
              d.name as department_name
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
    if ((actor.role || '').toUpperCase() !== 'ADMIN') {
      return res.status(403).json({ error: 'صلاحية إضافة المستخدمين محصورة بمدير النظام فقط' });
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

    const insertRes = await pool.query(
      `INSERT INTO users (
        user_id, username, password_hash, full_name, role, department_id, unit,
        is_active, is_read_only, can_add_transaction, is_department_manager,
        assigned_department_id, can_add_dept_members_transactions, is_deleted, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, FALSE, NOW())
      RETURNING user_id, username, full_name, role, department_id, unit, is_active,
                is_read_only, can_add_transaction, is_department_manager, assigned_department_id`,
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

    await logAudit('CREATE_USER', 'users', newUserId, actor.id || actor.user_id, actor.full_name, { username: cleanUsername });
    res.status(201).json({ success: true, message: 'تم حفظ المستخدم بنجاح', user: insertRes.rows[0] });
  } catch (err) {
    console.error('Create User Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ المستخدم: ' + (err.message || err) });
  }
});

// تعديل بيانات المستخدم (Admin Only)
app.put(['/api/users/:id', '/api/admin/users/:id', '/api/admin/users/update'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    if ((actor.role || '').toUpperCase() !== 'ADMIN') {
      return res.status(403).json({ error: 'صلاحية تعديل المستخدمين محصورة بمدير النظام فقط' });
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
    const q = `UPDATE users SET ${updates.join(', ')} WHERE user_id = $${idx} RETURNING user_id, username, full_name, role, department_id, unit, is_active`;
    const updRes = await pool.query(q, values);

    await logAudit('UPDATE_USER', 'users', targetId, actor.id || actor.user_id, actor.full_name, req.body);
    res.json({ success: true, message: 'تم تعديل بيانات المستخدم بنجاح', user: updRes.rows[0] });
  } catch (err) {
    console.error('Update User Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء تعديل المستخدم: ' + (err.message || err) });
  }
});

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

// تعديل عجلة (Admin Only)
app.put(['/api/vehicles/:id', '/api/admin/vehicles/:id'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    if ((actor.role || '').toUpperCase() !== 'ADMIN') {
      return res.status(403).json({ error: 'صلاحية تعديل العجلات محصورة بمدير النظام فقط' });
    }

    const vehId = req.params.id;
    const { plate_number, vehicle_type, department_id, current_km, is_active } = req.body;

    const updates = [];
    const values = [];
    let idx = 1;

    if (plate_number) {
      updates.push(`plate_number = $${idx++}`);
      values.push(String(plate_number).trim());
    }
    if (vehicle_type !== undefined) {
      updates.push(`vehicle_type = $${idx++}`);
      values.push(vehicle_type);
    }
    if (department_id !== undefined) {
      updates.push(`department_id = $${idx++}`);
      values.push(department_id || null);
    }
    if (current_km !== undefined) {
      updates.push(`current_km = $${idx++}`);
      values.push(parseInt(current_km, 10) || 0);
    }
    if (is_active !== undefined) {
      updates.push(`is_active = $${idx++}`);
      values.push(Boolean(is_active));
    }

    if (updates.length === 0) {
      return res.json({ success: true, message: 'لا توجد تعديلات' });
    }

    updates.push(`updated_at = NOW()`);
    values.push(vehId);

    const q = `UPDATE vehicles SET ${updates.join(', ')} WHERE vehicle_id = $${idx} AND is_deleted = FALSE RETURNING *`;
    const updRes = await pool.query(q, values);

    if (updRes.rows.length === 0) {
      return res.status(404).json({ error: 'العجلة غير موجودة' });
    }

    await logAudit('UPDATE_VEHICLE', 'vehicles', vehId, actor.id || actor.user_id, actor.full_name, req.body);
    res.json({ success: true, message: 'تم تعديل بيانات العجلة بنجاح', vehicle: updRes.rows[0] });
  } catch (err) {
    console.error('Update Vehicle Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء تعديل العجلة: ' + (err.message || err) });
  }
});

// إضافة عجلة جديدة (Admin Only)
app.post(['/api/vehicles', '/api/admin/vehicles', '/api/admin/vehicles/add'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    if ((actor.role || '').toUpperCase() !== 'ADMIN') {
      return res.status(403).json({ error: 'صلاحية إضافة العجلات محصورة بمدير النظام فقط' });
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
// 9. تقرير سجل صيانة العجلات الشامل للأدمن (Vehicle Maintenance Dossier)
// ==============================================================================
app.get('/api/reports/vehicle-history', authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const actorRole = (actor.role || '').toUpperCase();
    if (actorRole !== 'ADMIN') {
      return res.status(403).json({ error: 'عذراً، هذا التقرير مخصص لمدير النظام فقط' });
    }

    const { wheel_id } = req.query;

    let query = `
      SELECT t.*, 
             COALESCE(t.cost, 0) as maintenance_price,
             COALESCE(t.mileage, 0) as current_km,
             u.full_name as user_name,
             d.name as department_name
      FROM transactions t
      LEFT JOIN users u ON t.user_id = u.user_id
      LEFT JOIN departments d ON t.department_id = d.department_id
      WHERE t.is_deleted = FALSE
    `;
    const params = [];

    if (wheel_id && wheel_id.trim() !== '') {
      params.push(wheel_id.trim());
      query += ` AND t.wheel_id = $${params.length}`;
    }

    query += ` ORDER BY t.created_at DESC`;
    const txRes = await pool.query(query, params);

    // حساب الإحصائيات
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
        wheel_id: wheel_id || 'ALL'
      },
      transactions: txRes.rows
    });
  } catch (err) {
    console.error('Vehicle History Report Error:', err);
    res.status(500).json({ error: 'فشل استخراج التقرير: ' + (err.message || err) });
  }
});

// ==============================================================================
// 10. نظام الإشعارات الفورية (Notifications API)
// ==============================================================================
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const actorId = req.user.id || req.user.user_id;
    const notifs = await pool.query(
      `SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100`,
      [actorId]
    );
    res.json({ success: true, count: notifs.rows.length, notifications: notifs.rows });
  } catch (err) {
    console.error('Fetch Notifications Error:', err);
    res.status(500).json({ error: 'فشل جلب الإشعارات' });
  }
});

app.post('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const actorId = req.user.id || req.user.user_id;
    const notifId = req.params.id;
    await pool.query(
      `UPDATE notifications SET is_read = TRUE WHERE notification_id = $1 AND user_id = $2`,
      [notifId, actorId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'فشل تحديث حالة الإشعار' });
  }
});

app.post('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const actorId = req.user.id || req.user.user_id;
    await pool.query(
      `UPDATE notifications SET is_read = TRUE WHERE user_id = $1`,
      [actorId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'فشل تحديث الإشعارات' });
  }
});

// ==============================================================================
// 11. الحذف المنطقي وسلة المحذوفات (Soft Delete Pipeline)
// ==============================================================================
async function executeSoftDelete(req, res, { tableName, idColumn, entityType, recordId, successMsg }) {
  try {
    const actor = req.user;
    if ((actor.role || '').toUpperCase() !== 'ADMIN') {
      return res.status(403).json({ error: 'ليس لديك صلاحية تنفيذ الحذف، الحذف محصور بمدير النظام' });
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
       VALUES ($1, $2, $3, $4, NOW())`,
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
app.delete(['/api/users/:id', '/api/admin/users/:id'], authenticateToken, (req, res) => {
  const targetId = req.params.id;
  const actorId = req.user.id || req.user.user_id;
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
});

// حذف عجلة
app.delete(['/api/vehicles/:id', '/api/admin/vehicles/:id'], authenticateToken, (req, res) =>
  executeSoftDelete(req, res, {
    tableName: 'vehicles',
    idColumn: 'vehicle_id',
    entityType: 'vehicle',
    recordId: req.params.id,
    successMsg: 'تم نقل العجلة إلى جدول المحذوفات بنجاح'
  })
);

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
