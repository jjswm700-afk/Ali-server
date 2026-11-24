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

// تسجيل الطلبات الواردة في سجلات Render
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

// رفع حد استقبال البيانات لدعم صور الفواتير والمركبات المرفقة
const bodyLimit = process.env.BODY_LIMIT || '25mb';
app.use(express.json({ limit: bodyLimit }));
app.use(express.urlencoded({ extended: true, limit: bodyLimit }));

const JWT_SECRET = process.env.JWT_SECRET || 'wheel_default_secret_jwt_key_2026';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '30d';

// إعداد مجمع الاتصال بقاعدة بيانات PostgreSQL (Supabase)
const dbUrl = process.env.DATABASE_URL || '';
const isLocalhost = dbUrl.includes('localhost') || dbUrl.includes('127.0.0.1');
const pool = new Pool({
  connectionString: dbUrl,
  ssl: !isLocalhost ? { rejectUnauthorized: false } : false
});

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

// دالة تجزئة كلمات المرور (SHA-256)
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

// 0. المسار الرئيسي لفحص جاهزية السيرفر
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'online',
    system: 'Wheel Maintenance Cloud API',
    message: 'Server is running'
  });
});

// 1. فحص صحة وحالة السيرفر وقاعدة البيانات
app.get('/api/health', async (req, res) => {
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
    version: '2.1.0 (Cloud Edition)',
    database: dbStatus,
    timestamp: new Date().toISOString()
  });
});

// 2. تسجيل الدخول وإصدار رمز الدخول (Login)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'يرجى إدخال اسم المستخدم وكلمة المرور' });
    }

    const trimmedUser = String(username).trim();
    const userRes = await pool.query(
      `SELECT * FROM users WHERE LOWER(username) = LOWER($1) AND is_deleted = FALSE`,
      [trimmedUser]
    );

    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    const user = userRes.rows[0];

    if (!user.is_active) {
      return res.status(403).json({ error: 'الحساب معطل من قبل مدير النظام' });
    }

    const passHash = hashPassword(password);
    const isValid = (user.password_hash === passHash) || (password === '123' && user.password_hash === hashPassword('123'));

    if (!isValid) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    const tokenPayload = {
      id: user.user_id,
      user_id: user.user_id,
      username: user.username,
      full_name: user.full_name,
      role: user.role,
      department_id: user.department_id,
      is_read_only: user.is_read_only,
      can_add_transaction: user.can_add_transaction,
      is_department_manager: user.is_department_manager,
      assigned_department_id: user.assigned_department_id
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    await pool.query('UPDATE users SET last_login_at = NOW() WHERE user_id = $1', [user.user_id]);
    await logAudit('USER_LOGIN', 'users', user.user_id, user.user_id, user.full_name, { ip: req.ip });

    res.json({
      success: true,
      message: 'تم تسجيل الدخول بنجاح',
      token,
      user: tokenPayload
    });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ error: 'حدث خطأ في الخادم أثناء تسجيل الدخول' });
  }
});

// استعلام بيانات المستخدم الحالي
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const userRes = await pool.query(
      `SELECT user_id, username, full_name, role, department_id, unit, is_read_only, 
              can_add_transaction, is_department_manager, assigned_department_id 
       FROM users WHERE user_id = $1 AND is_deleted = FALSE`,
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

// 3. إضافة معاملة صيانة جديدة عن بُعد (Create Transaction)
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const {
      wheel_id,
      vehicle_numbers,
      department_id,
      description,
      cost,
      mileage,
      receipt_image,
      receipt_images,
      vehicle_images,
      category,
      member_user_id
    } = req.body;

    const actorId = req.user.id || req.user.user_id;

    const userRes = await pool.query('SELECT * FROM users WHERE user_id = $1', [actorId]);
    if (userRes.rows.length === 0 || !userRes.rows[0].is_active) {
      return res.status(403).json({ error: 'المستخدم غير مفعّل أو تم إيقافه' });
    }
    const user = userRes.rows[0];

    if (user.is_read_only) {
      return res.status(403).json({ error: 'حسابك مخصص للقراءة والاطلاع فقط، لا تملك صلاحية إضافة معاملات.' });
    }

    let targetUserId = user.user_id;
    let targetMemberId = null;
    let targetDept = department_id || user.assigned_department_id || user.department_id;

    if (member_user_id) {
      const isMgr = (user.is_department_manager || user.role === 'DEPARTMENT_HEAD' || user.role === 'ADMIN');
      const canAddMembers = (user.can_add_dept_members_transactions || user.role === 'ADMIN');
      if (!isMgr || !canAddMembers) {
        return res.status(403).json({ error: 'ليس لديك صلاحية إضافة معاملات لمنتسبي القسم.' });
      }

      const memRes = await pool.query('SELECT * FROM users WHERE user_id = $1 AND is_deleted = FALSE', [member_user_id]);
      if (memRes.rows.length === 0) {
        return res.status(404).json({ error: 'المنتسب المحدد غير موجود' });
      }
      const member = memRes.rows[0];

      if (user.role !== 'ADMIN' && member.department_id !== user.department_id && member.department_id !== user.assigned_department_id) {
        return res.status(403).json({ error: 'لا يمكنك إضافة معاملة لمنتسب تابع لقسم آخر.' });
      }

      targetUserId = member.user_id;
      targetMemberId = member.user_id;
      targetDept = member.department_id || targetDept;
    } else {
      if (!user.can_add_transaction && user.role !== 'ADMIN') {
        return res.status(403).json({ error: 'ليس لديك صلاحية لإضافة معاملات جديدة شخصية.' });
      }
    }

    const txId = 'TX-' + new Date().getFullYear() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const primaryWheel = wheel_id || (Array.isArray(vehicle_numbers) && vehicle_numbers.length > 0 ? vehicle_numbers[0] : 'عجلة غير محددة');

    const insertResult = await pool.query(
      `INSERT INTO transactions 
       (transaction_id, wheel_id, vehicle_numbers, department_id, user_id, member_user_id, created_by, 
        description, cost, mileage, receipt_image, receipt_images, vehicle_images, category, status, is_locked, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'PENDING_AUDITOR', TRUE, NOW())
       RETURNING *`,
      [
        txId,
        primaryWheel,
        JSON.stringify(vehicle_numbers || [primaryWheel]),
        targetDept,
        targetUserId,
        targetMemberId,
        actorId,
        description || '',
        parseFloat(cost) || 0.00,
        parseInt(mileage, 10) || 0,
        receipt_image || (Array.isArray(receipt_images) && receipt_images.length > 0 ? receipt_images[0] : null),
        JSON.stringify(receipt_images || (receipt_image ? [receipt_image] : [])),
        JSON.stringify(vehicle_images || []),
        category || 'إطارات وبطاريات'
      ]
    );

    const newTx = insertResult.rows[0];

    await logAudit('CREATE_TRANSACTION', 'transactions', txId, actorId, user.full_name, {
      cost: newTx.cost,
      wheel_id: primaryWheel,
      member_user_id: targetMemberId
    });

    res.status(201).json({
      success: true,
      message: 'تم إرسال المعاملة بنجاح إلى مدقق الوصولات للمطابقة والتدقيق',
      data: newTx,
      transaction: newTx
    });
  } catch (err) {
    console.error('Insert Transaction Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ المعاملة على السيرفر' });
  }
});

// 4. جلب المعاملات للمزامنة والعرض (Fetch Transactions)
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { status, limit = 200, offset = 0 } = req.query;
    const actor = req.user;

    let query = `
      SELECT t.*, 
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

    if (actor.role === 'USER') {
      params.push(actor.id || actor.user_id);
      query += ` AND (t.user_id = $${params.length} OR t.created_by = $${params.length})`;
    } else if (actor.role === 'DEPARTMENT_HEAD' || actor.role === 'Department_Head') {
      const dept = actor.assigned_department_id || actor.department_id;
      params.push(dept);
      query += ` AND t.department_id = $${params.length}`;
    }

    if (status) {
      params.push(status);
      query += ` AND t.status = $${params.length}`;
    }

    query += ` ORDER BY t.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(parseInt(limit, 10), parseInt(offset, 10));

    const result = await pool.query(query, params);
    res.json({ success: true, count: result.rows.length, data: result.rows });
  } catch (err) {
    console.error('Fetch Transactions Error:', err);
    res.status(500).json({ error: 'فشل جلب البيانات من السيرفر' });
  }
});

// 5. الحذف المنطقي الآمن للمعاملة (Soft Delete)
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const txId = req.params.id;
    const actor = req.user;

    const txRes = await pool.query('SELECT * FROM transactions WHERE transaction_id = $1 AND is_deleted = FALSE', [txId]);
    if (txRes.rows.length === 0) {
      return res.status(404).json({ error: 'المعاملة غير موجودة' });
    }
    const tx = txRes.rows[0];

    await pool.query(
      `INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by, deleted_at)
       VALUES ('transaction', $1, $2, $3, NOW())`,
      [txId, JSON.stringify(tx), actor.full_name || actor.username]
    );

    await pool.query(
      `UPDATE transactions SET is_deleted = TRUE, deleted_at = NOW(), deleted_by = $1 WHERE transaction_id = $2`,
      [actor.id || actor.user_id, txId]
    );

    await logAudit('SOFT_DELETE_TRANSACTION', 'transactions', txId, actor.id || actor.user_id, actor.full_name, {});

    res.json({ success: true, message: 'تم نقل المعاملة إلى سلة المحذوفات بنجاح' });
  } catch (err) {
    console.error('Delete Tx Error:', err);
    res.status(500).json({ error: 'فشل تنفيذ الحذف على السيرفر' });
  }
});

// 6. المزامنة الثنائية الكاملة للتطبيق والهاتف (Full Offline/Online Sync)
app.get('/api/sync', authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const since = req.query.since || '1970-01-01T00:00:00.000Z';

    const depts = await pool.query('SELECT * FROM departments WHERE is_deleted = FALSE');
    const vehs = await pool.query('SELECT * FROM vehicles WHERE is_deleted = FALSE');
    const users = await pool.query('SELECT user_id, username, full_name, department_id, role, is_active FROM users WHERE is_deleted = FALSE');

    let txQuery = `SELECT * FROM transactions WHERE is_deleted = FALSE AND updated_at >= $1`;
    const txParams = [since];

    if (actor.role === 'USER') {
      txParams.push(actor.id || actor.user_id);
      txQuery += ` AND (user_id = $2 OR created_by = $2)`;
    } else if (actor.role === 'DEPARTMENT_HEAD' || actor.role === 'Department_Head') {
      const dept = actor.assigned_department_id || actor.department_id;
      txParams.push(dept);
      txQuery += ` AND department_id = $2`;
    }

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

// 7. تشغيل السيرفر السحابي (Server Listen)
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`================================================================`);
  console.log(`  سيرفر صيانة العجلات السحابي (Wheel Maintenance Cloud API)`);
  console.log(`  يعمل بنجاح على المنفذ: ${PORT}`);
  console.log(`  البيئة: ${process.env.NODE_ENV || 'production'}`);
  console.log(`================================================================`);
});
