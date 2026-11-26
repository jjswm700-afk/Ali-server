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
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'x-user-role', 'x-user-id', 'x-idempotency-key']
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

// ==============================================================================
// 1. فحص صحة وحالة السيرفر (Health Check & Info) - عام ومفتوح للجميع بدون رمز دخول
// ==============================================================================
app.get(['/api/health', '/api/ping'], async (req, res) => {
  let dbStatus = 'disconnected';
  try {
    const dbRes = await pool.query('SELECT NOW() as db_time');
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

// ==============================================================================
// 2. تسجيل الدخول وإصدار رمز الدخول (Authentication - Login)
// ==============================================================================
app.post(['/api/auth/login', '/api/login'], async (req, res) => {
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

    // مطابقة كلمة المرور (التجزئة أو الرمز الافتراضي)
    const isValid = verifyPassword(password, user.password_hash);

    if (!isValid) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    // توليد رمز JWT
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

    // تحديث وقت آخر تسجيل دخول
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

// ==============================================================================
// 3. إضافة معاملة صيانة جديدة عن بُعد (Create Transaction)
// ==============================================================================
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { 
      vehicle_numbers,
      department_id, 
      receipt_images,
      vehicle_images,
      member_user_id
    } = req.body;

    const wheelId = req.body.wheel_id || req.body.vehicle_id || req.body.plate_number || (Array.isArray(vehicle_numbers) && vehicle_numbers.length > 0 ? vehicle_numbers[0] : 'عجلة غير محددة');
    const cost = req.body.cost !== undefined ? req.body.cost : (req.body.maintenance_price || 0);
    const mileage = req.body.mileage !== undefined ? req.body.mileage : (req.body.current_km || 0);
    const description = req.body.description !== undefined ? req.body.description : (req.body.notes || '');
    const category = req.body.category || req.body.maintenance_type || 'إطارات وبطاريات';
    const receipt_image = req.body.receipt_image || (Array.isArray(receipt_images) && receipt_images.length > 0 ? receipt_images[0] : null);
    const allReceipts = receipt_images || (receipt_image ? [receipt_image] : []);
    const allVehicleImgs = vehicle_images || [];
    const status = req.body.status || 'PENDING_AUDITOR';
    const is_locked = req.body.is_locked !== undefined ? Boolean(req.body.is_locked) : true;
    const auditor_note = req.body.auditor_note || '';
    const admin_note = req.body.admin_note || '';
    const txId = req.body.transaction_id || ('TX-' + new Date().getFullYear() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase());

    const actorId = req.user.id || req.user.user_id;

    // استرجاع صلاحيات المستخدم الحالية من قاعدة البيانات
    const userRes = await pool.query('SELECT * FROM users WHERE user_id = $1', [actorId]);
    if (userRes.rows.length === 0 || !userRes.rows[0].is_active) {
      return res.status(403).json({ error: 'المستخدم غير مفعّل أو تم إيقافه' });
    }
    const user = userRes.rows[0];

    // التحقق من صلاحية القراءة فقط (Read-Only)
    if (user.is_read_only) {
      return res.status(403).json({ error: 'حسابك مخصص للقراءة والاطلاع فقط، لا تملك صلاحية إضافة معاملات.' });
    }

    // التحقق من صلاحيات مسؤول القسم عند الإضافة لمنتسب
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

    const primaryWheel = wheelId;
    const allWheels = vehicle_numbers || [primaryWheel];

    const insertResult = await pool.query(
      `INSERT INTO transactions 
       (transaction_id, wheel_id, vehicle_numbers, department_id, user_id, member_user_id, created_by, 
        description, cost, mileage, receipt_image, receipt_images, vehicle_images, category, status, is_locked, 
        auditor_note, admin_note, is_deleted, created_at, updated_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, FALSE, NOW(), $19)
       ON CONFLICT (transaction_id) DO UPDATE SET
         wheel_id = EXCLUDED.wheel_id,
         vehicle_numbers = EXCLUDED.vehicle_numbers,
         category = EXCLUDED.category,
         cost = EXCLUDED.cost,
         mileage = EXCLUDED.mileage,
         description = EXCLUDED.description,
         receipt_image = EXCLUDED.receipt_image,
         receipt_images = EXCLUDED.receipt_images,
         vehicle_images = EXCLUDED.vehicle_images,
         status = EXCLUDED.status,
         auditor_note = COALESCE(EXCLUDED.auditor_note, transactions.auditor_note),
         admin_note = COALESCE(EXCLUDED.admin_note, transactions.admin_note),
         is_locked = EXCLUDED.is_locked,
         updated_by = EXCLUDED.updated_by,
         updated_at = NOW()
       RETURNING *`,
      [
        txId,
        primaryWheel,
        JSON.stringify(allWheels),
        targetDept,
        targetUserId,
        targetMemberId,
        actorId,
        description || '',
        parseFloat(cost) || 0.00,
        parseInt(mileage, 10) || 0,
        receipt_image,
        JSON.stringify(allReceipts),
        JSON.stringify(allVehicleImgs),
        category,
        status,
        is_locked,
        auditor_note,
        admin_note,
        actorId
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
      message: 'تم حفظ ومزامنة المعاملة بنجاح على السيرفر السحابي',
      data: newTx,
      transaction: newTx
    });
  } catch (err) {
    console.error('Insert Transaction Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ المعاملة على السيرفر: ' + (err.message || err) });
  }
});

// ==============================================================================
// 4. جلب المعاملات للمزامنة والعرض (Fetch Transactions)
// ==============================================================================
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { status, limit = 200, offset = 0 } = req.query;
    const actor = req.user;

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

    // تقييد العرض حسب دور المستخدم ونطاق القسم
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

// ==============================================================================
// 5. الحذف المنطقي الآمن للمعاملة (Soft Delete)
// ==============================================================================
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    if (actor.role !== 'admin' && actor.role !== 'ADMIN' && !actor.is_admin) {
      return res.status(403).json({ error: 'عذراً، صلاحية حذف المعاملات مخصصة للأدمن فقط' });
    }
    const txId = req.params.id;

    const txRes = await pool.query('SELECT * FROM transactions WHERE transaction_id = $1 AND is_deleted = FALSE', [txId]);
    if (txRes.rows.length === 0) {
      return res.status(404).json({ error: 'المعاملة غير موجودة' });
    }
    const tx = txRes.rows[0];

    // الحفظ في سلة المحذوفات
    await pool.query(
      `INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by, deleted_at)
       VALUES ('transaction', $1, $2, $3, NOW())`,
      [txId, JSON.stringify(tx), actor.full_name || actor.username]
    );

    // تطبيق الحذف المنطقي
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

// ==============================================================================
// 6. المزامنة الثنائية الكاملة للتطبيق والهاتف (Full Offline/Online Sync)
// ==============================================================================
app.get('/api/sync', authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const isFullSync = req.query.full === '1' || !req.query.since;
    const since = req.query.since || '1970-01-01T00:00:00.000Z';

    const depts = await pool.query('SELECT * FROM departments WHERE is_deleted = FALSE ORDER BY created_at DESC');
    const vehs = await pool.query('SELECT * FROM vehicles WHERE is_deleted = FALSE ORDER BY plate_number ASC');
    const users = await pool.query(
      SELECT user_id, username, full_name, department_id, unit, role, is_active,
              is_read_only, can_add_transaction, is_department_manager, assigned_department_id,
              can_add_dept_members_transactions, is_deleted, created_at
       FROM users WHERE is_deleted = FALSE ORDER BY created_at DESC
    );

    // استخدام COALESCE لضمان جلب السجلات حتى لو كان updated_at فارغاً (NULL)
    let txQuery = 
      SELECT t.*, u.full_name as user_name, d.name as department_name
      FROM transactions t
      LEFT JOIN users u ON t.user_id = u.user_id
      LEFT JOIN departments d ON t.department_id = d.department_id
      WHERE t.is_deleted = FALSE
    ;
    const txParams = [];

    if (!isFullSync) {
      txParams.push(since);
      txQuery +=  AND COALESCE(t.updated_at, t.created_at) >= {txParams.length};
    }

    if (actor.role === 'USER') {
      txParams.push(actor.id || actor.user_id);
      txQuery +=  AND (t.user_id = {txParams.length} OR t.created_by = {txParams.length});
    } else if (actor.role === 'DEPARTMENT_HEAD' || actor.role === 'Department_Head') {
      const dept = actor.assigned_department_id || actor.department_id;
      txParams.push(dept);
      txQuery +=  AND t.department_id = {txParams.length};
    }

    txQuery +=  ORDER BY t.created_at DESC LIMIT 1000;
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

// ==============================================================================
// إدارة الأقسام (إنشاء وحفظ دائم في قاعدة البيانات)
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
    if (actor.role !== 'ADMIN') {
      return res.status(403).json({ error: 'صلاحية إضافة الأقسام محصورة بمدير النظام فقط' });
    }

    const { department_id, name, code } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'يرجى إدخال اسم القسم' });
    }

    const newDeptId = department_id || ('DEPT-' + crypto.randomBytes(3).toString('hex').toUpperCase());
    const insertRes = await pool.query(
      INSERT INTO departments (department_id, name, code, is_deleted, created_at)
       VALUES (, , , FALSE, NOW())
       ON CONFLICT (department_id) DO UPDATE SET
         name = EXCLUDED.name,
         is_deleted = FALSE
       RETURNING *,
      [newDeptId, String(name).trim(), code || newDeptId]
    );

    await logAudit('CREATE_DEPARTMENT', 'departments', newDeptId, actor.id || actor.user_id, actor.full_name, { name });
    res.status(201).json({ success: true, message: 'تم حفظ القسم في السحابة بنجاح', data: insertRes.rows[0], department: insertRes.rows[0] });
  } catch (err) {
    console.error('Create Department Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ القسم على السيرفر' });
  }
});

// ==============================================================================
// إدارة أسطول العجلات (إنشاء وحفظ دائم في قاعدة البيانات)
// ==============================================================================
app.get(['/api/vehicles', '/api/admin/vehicles'], async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM vehicles WHERE is_deleted = FALSE ORDER BY plate_number ASC');
    res.json({ success: true, data: r.rows, vehicles: r.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post(['/api/vehicles', '/api/admin/vehicles', '/api/admin/vehicles/add', '/api/admin/vehicles/update'], authenticateToken, async (req, res) => {
  try {
    const { vehicle_id, id, plate_number, plate, vehicle_type, department_id, current_km, is_active } = req.body;
    const finalPlate = String(plate_number || plate || vehicle_id || id || '').trim();
    if (!finalPlate) {
      return res.status(400).json({ error: 'يرجى إدخال رقم العجلة أو اللوحة' });
    }

    const newVehId = vehicle_id || id || finalPlate;
    const insertRes = await pool.query(
      INSERT INTO vehicles (vehicle_id, plate_number, vehicle_type, department_id, current_km, is_active, is_deleted, created_at)
       VALUES (, , , , , , FALSE, NOW())
       ON CONFLICT (vehicle_id) DO UPDATE SET
         plate_number = EXCLUDED.plate_number,
         vehicle_type = EXCLUDED.vehicle_type,
         department_id = EXCLUDED.department_id,
         current_km = EXCLUDED.current_km,
         is_active = EXCLUDED.is_active,
         is_deleted = FALSE,
         updated_at = NOW()
       RETURNING *,
      [newVehId, finalPlate, vehicle_type || 'عجلة', department_id || null, parseInt(current_km, 10) || 0, is_active !== false && is_active !== 0]
    );

    res.status(201).json({ success: true, message: 'تم حفظ العجلة بنجاح', data: insertRes.rows[0], vehicle: insertRes.rows[0] });
  } catch (err) {
    console.error('Create Vehicle Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ العجلة على السيرفر' });
  }
});

// ==============================================================================
// إدارة المستخدمين (إنشاء وتعديل وحفظ دائم في قاعدة البيانات)
// ==============================================================================
app.get(['/api/users', '/api/admin/users'], authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      SELECT user_id, username, full_name, role, department_id, unit, is_active, 
              is_read_only, can_add_transaction, is_department_manager, 
              assigned_department_id, can_add_dept_members_transactions, is_deleted, created_at
       FROM users WHERE is_deleted = FALSE ORDER BY created_at DESC
    );
    res.json({ success: true, data: result.rows, users: result.rows });
  } catch (err) {
    console.error('Fetch Users Error:', err);
    res.status(500).json({ error: 'فشل جلب قائمة المستخدمين' });
  }
});

app.post(['/api/users', '/api/admin/users', '/api/admin/users/add', '/api/admin/users/create'], authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    if (actor.role !== 'ADMIN') {
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

    if (!username || !full_name) {
      return res.status(400).json({ error: 'يرجى إدخال اسم المستخدم والاسم الكامل' });
    }

    const cleanUsername = String(username).trim();
    const dupCheck = await pool.query(
      'SELECT user_id FROM users WHERE LOWER(username) = LOWER() AND is_deleted = FALSE',
      [cleanUsername]
    );
    if (dupCheck.rows.length > 0) {
      return res.status(409).json({ error: 'اسم المستخدم مسجل مسبقاً، يرجى اختيار اسم آخر' });
    }

    const newUserId = user_id || ('USR-' + crypto.randomBytes(3).toString('hex').toUpperCase());
    const passHash = hashPassword(password || '123');

    const finalDept = department_id || department || null;
    const insertRes = await pool.query(
      INSERT INTO users (
        user_id, username, password_hash, full_name, role, department_id, unit,
        is_active, is_read_only, can_add_transaction, is_department_manager,
        assigned_department_id, can_add_dept_members_transactions, is_deleted, created_at
      ) VALUES (, , , , , , , , , , , , , FALSE, NOW())
      RETURNING user_id, username, full_name, role, department_id, unit, is_active,
                is_read_only, can_add_transaction, is_department_manager, assigned_department_id,
      [
        newUserId,
        cleanUsername,
        passHash,
        String(full_name).trim(),
        role || 'USER',
        finalDept,
        unit || '',
        is_active !== false && is_active !== 0,
        Boolean(is_read_only),
        can_add_transaction !== false && can_add_transaction !== 0,
        Boolean(is_department_manager),
        assigned_department_id || finalDept,
        Boolean(can_add_dept_members_transactions)
      ]
    );

    await logAudit('CREATE_USER', 'users', newUserId, actor.id || actor.user_id, actor.full_name, { username: cleanUsername });
    res.status(201).json({ success: true, message: 'تم حفظ المستخدم في السحابة بنجاح', data: insertRes.rows[0], user: insertRes.rows[0] });
  } catch (err) {
    console.error('Create User Error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ المستخدم على السيرفر' });
  }
});

// ==============================================================================
// 6.3 Soft Delete & Deleted Records Pipeline (SRS Axis 3 & 4)
// ==============================================================================

async function executeSoftDelete(req, res, { tableName, idColumn, entityType, recordId, successMsg }) {
  try {
    const actor = req.user;
    if (actor.role !== 'ADMIN' && !actor.is_department_manager) {
      return res.status(403).json({ error: 'ليس لديك صلاحية تنفيذ الحذف' });
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

// 1. حذف عجلة
app.delete(['/api/vehicles/:id', '/api/admin/vehicles/:id'], authenticateToken, (req, res) =>
  executeSoftDelete(req, res, {
    tableName: 'vehicles',
    idColumn: 'vehicle_id',
    entityType: 'vehicle',
    recordId: req.params.id,
    successMsg: 'تم نقل العجلة إلى جدول المحذوفات بنجاح'
  })
);
app.post('/api/admin/vehicles/delete', authenticateToken, (req, res) => {
  const id = req.body.vehicle_id || req.body.id || req.body.plate;
  return executeSoftDelete(req, res, {
    tableName: 'vehicles',
    idColumn: 'vehicle_id',
    entityType: 'vehicle',
    recordId: id,
    successMsg: 'تم نقل العجلة إلى جدول المحذوفات بنجاح'
  });
});

// 2. حذف مستخدم
app.delete(['/api/users/:id', '/api/admin/users/:id'], authenticateToken, (req, res) => {
  const targetId = req.params.id;
  if (String(targetId) === String(req.user.id || req.user.user_id)) {
    return res.status(400).json({ error: 'لا يمكنك حذف حسابك الشخصي أثناء تسجيل الدخول' });
  }
  return executeSoftDelete(req, res, {
    tableName: 'users',
    idColumn: 'user_id',
    entityType: 'user',
    recordId: targetId,
    successMsg: 'تم نقل المستخدم إلى جدول المحذوفات بنجاح'
  });
});
app.post('/api/admin/users/delete', authenticateToken, (req, res) => {
  const targetId = req.body.user_id || req.body.id || req.body.username;
  if (String(targetId) === String(req.user.id || req.user.user_id)) {
    return res.status(400).json({ error: 'لا يمكنك حذف حسابك الشخصي أثناء تسجيل الدخول' });
  }
  return executeSoftDelete(req, res, {
    tableName: 'users',
    idColumn: 'user_id',
    entityType: 'user',
    recordId: targetId,
    successMsg: 'تم نقل المستخدم إلى جدول المحذوفات بنجاح'
  });
});

// 3. حذف قسم
app.delete(['/api/departments/:id', '/api/admin/departments/:id'], authenticateToken, (req, res) =>
  executeSoftDelete(req, res, {
    tableName: 'departments',
    idColumn: 'department_id',
    entityType: 'department',
    recordId: req.params.id,
    successMsg: 'تم نقل القسم إلى جدول المحذوفات بنجاح'
  })
);
app.post('/api/admin/departments/delete', authenticateToken, (req, res) => {
  const id = req.body.department_id || req.body.id || req.body.name;
  return executeSoftDelete(req, res, {
    tableName: 'departments',
    idColumn: 'department_id',
    entityType: 'department',
    recordId: id,
    successMsg: 'تم نقل القسم إلى جدول المحذوفات بنجاح'
  });
});

// 4. جلب سجل المحذوفات
app.get(['/api/deleted-records', '/api/admin/recycle-bin'], authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM deleted_records ORDER BY deleted_at DESC LIMIT 500`
    );
    res.json({ success: true, count: result.rows.length, data: result.rows, deleted_records: result.rows });
  } catch (err) {
    console.error('Fetch Deleted Records Error:', err);
    res.status(500).json({ error: 'فشل جلب سجل المحذوفات من السيرفر' });
  }
});

// 5. استعادة سجل محذوف
app.post(['/api/deleted-records/:id/restore', '/api/admin/recycle-bin/restore'], authenticateToken, async (req, res) => {
  try {
    const recordPk = req.params.id || req.body.id || req.body.trashId;
    const actor = req.user;

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
    if (!target) {
      return res.status(400).json({ error: 'نوع السجل غير مدعوم للاستعادة' });
    }

    await pool.query(
      `UPDATE ${target.table} SET is_deleted = FALSE, deleted_at = NULL, deleted_by = NULL WHERE ${target.col} = $1`,
      [item.entity_id]
    );

    await pool.query('DELETE FROM deleted_records WHERE id = $1', [recordPk]);

    res.json({ success: true, message: 'تمت استعادة السجل بنجاح وإعادته إلى القائمة النشطة' });
  } catch (err) {
    console.error('Restore Record Error:', err);
    res.status(500).json({ error: 'فشل استعادة السجل من السيرفر' });
  }
});

// 6. اعتماد أو تعديل حالة المعاملة للمدقق والأدمن
app.put(['/api/transactions/:id', '/api/transactions/:id/status', '/api/transactions/:id/approve'], authenticateToken, async (req, res) => {
  try {
    const txId = req.params.id;
    const body = req.body;
    const actor = req.user;
    const actorId = actor.id || actor.user_id;

    const updates = [];
    const values = [];
    let pIdx = 1;

    const wheelId = body.wheel_id || body.vehicle_id || body.plate_number;
    if (wheelId !== undefined) {
      updates.push(`wheel_id = $${pIdx++}`);
      values.push(wheelId);
    }
    const cost = body.cost !== undefined ? body.cost : body.maintenance_price;
    if (cost !== undefined) {
      updates.push(`cost = $${pIdx++}`);
      values.push(parseFloat(cost) || 0);
    }
    const mileage = body.mileage !== undefined ? body.mileage : body.current_km;
    if (mileage !== undefined) {
      updates.push(`mileage = $${pIdx++}`);
      values.push(parseInt(mileage, 10) || 0);
    }
    const desc = body.description !== undefined ? body.description : body.notes;
    if (desc !== undefined) {
      updates.push(`description = $${pIdx++}`);
      values.push(desc);
    }
    if (body.category !== undefined) {
      updates.push(`category = $${pIdx++}`);
      values.push(body.category);
    }
    if (body.receipt_image !== undefined) {
      updates.push(`receipt_image = $${pIdx++}`);
      values.push(body.receipt_image);
    }
    if (body.receipt_images !== undefined) {
      updates.push(`receipt_images = $${pIdx++}`);
      values.push(JSON.stringify(body.receipt_images));
    }
    if (body.vehicle_images !== undefined) {
      updates.push(`vehicle_images = $${pIdx++}`);
      values.push(JSON.stringify(body.vehicle_images));
    }
    if (body.status !== undefined) {
      updates.push(`status = $${pIdx++}`);
      values.push(body.status);
    }
    if (body.auditor_note !== undefined) {
      updates.push(`auditor_note = $${pIdx++}`);
      values.push(body.auditor_note);
    }
    if (body.admin_note !== undefined) {
      updates.push(`admin_note = $${pIdx++}`);
      values.push(body.admin_note);
    }
    if (body.is_locked !== undefined) {
      updates.push(`is_locked = $${pIdx++}`);
      values.push(Boolean(body.is_locked));
    }

    if (actor.role === 'AUDITOR') {
      updates.push(`audited_by_auditor_at = NOW()`);
    } else if (actor.role === 'ADMIN') {
      updates.push(`audited_at = NOW()`);
    }

    updates.push(`updated_by = $${pIdx++}`);
    values.push(actorId);

    updates.push(`updated_at = NOW()`);
    values.push(txId);

    const q = `UPDATE transactions SET ${updates.join(', ')} WHERE transaction_id = $${pIdx} AND is_deleted = FALSE RETURNING *`;
    const r = await pool.query(q, values);

    if (r.rows.length === 0) {
      return res.status(404).json({ error: 'المعاملة غير موجودة أو تم حذفها' });
    }

    res.json({ success: true, transaction: r.rows[0], message: 'تم تحديث حالة المعاملة بنجاح' });
  } catch (err) {
    console.error('Update Tx Status Error:', err);
    res.status(500).json({ error: 'فشل تحديث حالة المعاملة: ' + (err.message || err) });
  }
});

// 7. مزامنة المعاملات ورفع طابور الأوفلاين
app.post('/api/sync/push', authenticateToken, async (req, res) => {
  try {
    const items = req.body.items || [];
    const actor = req.user;
    let savedCount = 0;

    for (const item of items) {
      // 1. Transaction upsert with Supabase matching schema
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
        continue;
      }

      // 2. Polymorphic queue action
      const action = String(item.action || '').toUpperCase();
      if (action === 'CREATE_DEPARTMENT') {
        const dId = item.department_id || ('DEPT-' + crypto.randomBytes(3).toString('hex').toUpperCase());
        const dName = String(item.name || '').trim();
        if (dName) {
          await pool.query(
            `INSERT INTO departments (department_id, name, code, is_deleted, created_at)
             VALUES ($1, $2, $1, FALSE, NOW())
             ON CONFLICT (department_id) DO UPDATE SET name = EXCLUDED.name, is_deleted = FALSE`,
            [dId, dName]
          );
          savedCount++;
        }
      } else if (action === 'CREATE_USER') {
        const u = item.payload || item;
        const uId = u.user_id || ('USR-' + crypto.randomBytes(3).toString('hex').toUpperCase());
        const uName = String(u.username || '').trim();
        if (uName) {
          const passHash = hashPassword(u.password || '123');
          await pool.query(
            `INSERT INTO users (
              user_id, username, password_hash, full_name, role, department_id, unit,
              is_active, is_read_only, can_add_transaction, is_department_manager,
              assigned_department_id, can_add_dept_members_transactions, is_deleted, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, FALSE, NOW())
            ON CONFLICT (username) DO UPDATE SET
              full_name = EXCLUDED.full_name,
              role = EXCLUDED.role,
              department_id = EXCLUDED.department_id,
              is_active = EXCLUDED.is_active,
              is_deleted = FALSE`,
            [
              uId, uName, passHash, String(u.full_name || uName).trim(),
              u.role || 'USER', u.department_id || u.department || null, u.unit || '',
              u.is_active !== false && u.is_active !== 0, Boolean(u.is_read_only),
              u.can_add_transaction !== false && u.can_add_transaction !== 0,
              Boolean(u.is_department_manager), u.assigned_department_id || null,
              Boolean(u.can_add_dept_members_transactions)
            ]
          );
          savedCount++;
        }
      } else if (action === 'CREATE_VEHICLE') {
        const v = item.payload || item;
        const plate = String(v.plate_number || v.plate || '').trim();
        if (plate) {
          const vId = v.vehicle_id || plate;
          await pool.query(
            `INSERT INTO vehicles (vehicle_id, plate_number, vehicle_type, department_id, current_km, is_active, is_deleted, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, FALSE, NOW())
             ON CONFLICT (vehicle_id) DO UPDATE SET
               plate_number = EXCLUDED.plate_number,
               vehicle_type = EXCLUDED.vehicle_type,
               department_id = EXCLUDED.department_id,
               current_km = EXCLUDED.current_km,
               is_active = EXCLUDED.is_active,
               is_deleted = FALSE,
               updated_at = NOW()`,
            [vId, plate, v.vehicle_type || 'عجلة', v.department_id || null, parseInt(v.current_km, 10) || 0, v.is_active !== false && v.is_active !== 0]
          );
          savedCount++;
        }
      } else if (action === 'DELETE') {
        const entType = String(item.entity_type || '').toLowerCase();
        const entId = String(item.entity_id || '').trim();
        if (entId) {
          if (entType === 'department') {
            await pool.query('UPDATE departments SET is_deleted = TRUE, deleted_at = NOW() WHERE department_id = $1 OR name = $1', [entId]);
          } else if (entType === 'user') {
            await pool.query('UPDATE users SET is_deleted = TRUE, deleted_at = NOW() WHERE user_id = $1 OR username = $1', [entId]);
          } else if (entType === 'vehicle') {
            await pool.query('UPDATE vehicles SET is_deleted = TRUE, deleted_at = NOW() WHERE vehicle_id = $1 OR plate_number = $1', [entId]);
          } else if (entType === 'transaction') {
            await pool.query('UPDATE transactions SET is_deleted = TRUE, deleted_at = NOW() WHERE transaction_id = $1', [entId]);
          }
          savedCount++;
        }
      }
    }

    res.json({ success: true, count: savedCount, message: `تمت معالجة ومزامنة ${savedCount} عملية بنجاح ☁️` });
  } catch (err) {
    console.error('Sync Push Error:', err);
    res.status(500).json({ error: 'فشلت عملية المزامنة السحابية للبيانات: ' + (err.message || err) });
  }
});

// 8. مسار التهيئة الأولية والرفع الشامل (Push-All Initial Setup)
app.post('/api/sync/push-all', authenticateToken, async (req, res) => {
  try {
    const actor = req.user;
    const { users = [], departments = [], vehicles = [], transactions = [] } = req.body;
    let counts = { users: 0, departments: 0, vehicles: 0, transactions: 0 };

    // 1. الأقسام
    for (const d of departments) {
      const dId = d.department_id || d.id || ('DEPT-' + crypto.randomBytes(3).toString('hex').toUpperCase());
      const dName = String(d.name || '').trim();
      if (dName) {
        await pool.query(
          `INSERT INTO departments (department_id, name, code, is_deleted, created_at)
           VALUES ($1, $2, $3, FALSE, NOW())
           ON CONFLICT (department_id) DO UPDATE SET 
             name = EXCLUDED.name,
             is_deleted = FALSE`,
          [dId, dName, d.code || dId]
        );
        counts.departments++;
      }
    }

    // 2. المستخدمون
    for (const u of users) {
      const uId = u.user_id || u.id || ('USR-' + crypto.randomBytes(3).toString('hex').toUpperCase());
      const uName = String(u.username || '').trim();
      if (uName) {
        const passHash = u.password_hash || hashPassword(u.password || '123');
        await pool.query(
          `INSERT INTO users (
            user_id, username, password_hash, full_name, role, department_id, unit,
            is_active, is_read_only, can_add_transaction, is_department_manager,
            assigned_department_id, can_add_dept_members_transactions, can_edit_dept_transactions,
            is_deleted, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, FALSE, NOW())
          ON CONFLICT (username) DO UPDATE SET
            full_name = EXCLUDED.full_name,
            role = EXCLUDED.role,
            department_id = EXCLUDED.department_id,
            is_active = EXCLUDED.is_active,
            can_add_transaction = EXCLUDED.can_add_transaction,
            is_deleted = FALSE`,
          [
            uId, uName, passHash, String(u.full_name || uName).trim(),
            u.role || 'USER', u.department_id || null, u.unit || '',
            u.is_active !== false && u.is_active !== 0, Boolean(u.is_read_only),
            u.can_add_transaction !== false && u.can_add_transaction !== 0,
            Boolean(u.is_department_manager), u.assigned_department_id || null,
            Boolean(u.can_add_dept_members_transactions), Boolean(u.can_edit_dept_transactions)
          ]
        );
        counts.users++;
      }
    }

    // 3. العجلات
    for (const v of vehicles) {
      const plate = String(v.plate_number || v.plate || v.wheel_id || '').trim();
      if (plate) {
        const vId = v.vehicle_id || plate;
        await pool.query(
          `INSERT INTO vehicles (vehicle_id, plate_number, vehicle_type, department_id, current_km, is_active, is_deleted, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, FALSE, NOW())
           ON CONFLICT (vehicle_id) DO UPDATE SET
             plate_number = EXCLUDED.plate_number,
             vehicle_type = EXCLUDED.vehicle_type,
             department_id = EXCLUDED.department_id,
             current_km = EXCLUDED.current_km,
             is_active = EXCLUDED.is_active,
             is_deleted = FALSE,
             updated_at = NOW()`,
          [
            vId,
            plate,
            v.vehicle_type || 'عجلة',
            v.department_id || null,
            parseInt(v.current_km || v.mileage, 10) || 0,
            v.is_active !== false && v.is_active !== 0
          ]
        );
        counts.vehicles++;
      }
    }

    // 4. المعاملات
    for (const item of transactions) {
      const txId = item.transaction_id || ('TX-' + new Date().getFullYear() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase());
      const wheelId = item.wheel_id || item.vehicle_id || item.plate_number || (Array.isArray(item.vehicle_numbers) && item.vehicle_numbers.length > 0 ? item.vehicle_numbers[0] : 'عجلة غير محددة');
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
        txId,
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
      counts.transactions++;
    }

    res.json({
      success: true,
      message: `تم رفع ومزامنة التهيئة الأولية بنجاح (${counts.departments} قسم، ${counts.users} مستخدم، ${counts.vehicles} عجلة، ${counts.transactions} معاملة) ☁️`,
      counts
    });
  } catch (err) {
    console.error('Push All Error:', err);
    res.status(500).json({ error: 'فشل رفع البيانات الأولية: ' + (err.message || err) });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`================================================================`);
  console.log(`  سيرفر صيانة العجلات السحابي (Wheel Maintenance Cloud API)`);
  console.log(`  يعمل بنجاح على المنفذ: ${PORT}`);
  console.log(`  البيئة: ${process.env.NODE_ENV || 'production'}`);
  console.log(`================================================================`);
});
