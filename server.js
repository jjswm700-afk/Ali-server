// ==============================================================================
// Wheel Maintenance & Purchasing Documentation System (PRD/SRS v2.0 - Advanced)
// Backend Server - Node.js 24 with native node:sqlite
// Architecture: 3-Tier Workflow (User -> Intermediate Auditor -> Admin)
// ==============================================================================

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const XLSX = require('./public/js/xlsx.full.min.js');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data', 'maintenance.db');

if (!fs.existsSync(path.dirname(DB_FILE))) {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
}

function checkIsAdmin(req, parsedUrl, body = {}) {
  const roleHeader = (req.headers['x-user-role'] || req.headers['x-role'] || '').toString().trim().toUpperCase();
  if (roleHeader === 'ADMIN') return true;
  if (roleHeader && roleHeader !== 'ADMIN') return false;

  const roleQuery = (parsedUrl.searchParams.get('role') || parsedUrl.searchParams.get('view_role') || '').trim().toUpperCase();
  if (roleQuery === 'ADMIN') return true;
  if (roleQuery && roleQuery !== 'ADMIN') return false;

  const bodyRole = (body.role || body.user_role || '').toString().trim().toUpperCase();
  if (bodyRole === 'ADMIN') return true;
  if (bodyRole && bodyRole !== 'ADMIN') return false;

  const userId = (body.admin_id || body.user_id || req.headers['x-user-id'] || parsedUrl.searchParams.get('user_id') || '').toString().trim();
  if (userId) {
    const u = db.prepare('SELECT role FROM users WHERE user_id = ? OR username = ?').get(userId, userId);
    if (u && (u.role === 'ADMIN' || u.role.toUpperCase() === 'ADMIN')) return true;
    if (u && u.role && u.role.toUpperCase() !== 'ADMIN') return false;
  }
  return false;
}

function hashPassword(password) {
  const salt = 'wheel_security_salt_2026';
  return crypto.createHash('sha256').update(password + salt).digest('hex');
}

function verifyPassword(password, storedHash) {
  if (hashPassword(password) === storedHash) return true;
  // Support both short passcode ('123' / '123456') and full password for default roles
  if (password === '123' && (
    storedHash === hashPassword('admin123') ||
    storedHash === hashPassword('auditor123') ||
    storedHash === hashPassword('123456') ||
    storedHash === hashPassword('123')
  )) return true;
  if (password === '123456' && (
    storedHash === hashPassword('123') ||
    storedHash === hashPassword('123456') ||
    storedHash === hashPassword('admin123')
  )) return true;
  if (password === 'admin123' && (storedHash === hashPassword('123') || storedHash === hashPassword('admin123'))) return true;
  if (password === 'auditor123' && (storedHash === hashPassword('123') || storedHash === hashPassword('auditor123'))) return true;
  return false;
}

// ------------------------------------------------------------------------------
// Database Initialization
// ------------------------------------------------------------------------------
const db = new DatabaseSync(DB_FILE);

// Safe startup migrations for columns and seeds
try {
  const canonicalDepts = [
    ['DEPT-000', 'إدارة الصيانة والآليات المركزية'],
    ['DEPT-001', 'قسم النقل والآليات'],
    ['DEPT-002', 'قسم الخدمات والآليات التخصصية'],
    ['DEPT-003', 'شعبة التدقيق والرقابة المالية'],
    ['DEPT-004', 'قسم الخدمات الإدارية']
  ];
  for (const [dId, dName] of canonicalDepts) {
    const existing = db.prepare('SELECT department_id FROM departments WHERE department_id = ? OR name = ?').get(dId, dName);
    if (!existing) {
      db.prepare("INSERT INTO departments (department_id, name, created_at) VALUES (?, ?, datetime('now'))").run(dId, dName);
    } else {
      db.prepare('UPDATE departments SET department_id = ? WHERE name = ? AND department_id != ?').run(dId, dName, dId);
    }
  }
  db.prepare("UPDATE users SET full_name = 'سرمد كريم عبد الحسين', department = 'DEPT-002' WHERE username = 'sarmad'").run();
  const userDeptMap = [
    ['admin', 'DEPT-000'],
    ['user1', 'DEPT-001'],
    ['user2', 'DEPT-002'],
    ['علي', 'DEPT-001'],
    ['auditor1', 'DEPT-003'],
    ['head1', 'DEPT-001'],
    ['dept_head_test', 'DEPT-001'],
    ['مراد', 'DEPT-004'],
    ['ابو تحسين', 'DEPT-bbed24e3'],
    ['علاوي', 'DEPT-bbed24e3']
  ];
  for (const [uName, uDept] of userDeptMap) {
    db.prepare('UPDATE users SET department = ? WHERE username = ?').run(uDept, uName);
  }
  db.prepare("UPDATE vehicles SET department_id = 'DEPT-001' WHERE department_id IS NULL OR department_id = ''").run();
} catch (migErr) {
  console.warn('Startup migration note:', migErr.message);
}

try { db.exec('ALTER TABLE maintenance_transactions ADD COLUMN current_km INTEGER DEFAULT 0;'); } catch(e) {}
try { db.exec('ALTER TABLE maintenance_categories ADD COLUMN default_replacement_km INTEGER NOT NULL DEFAULT 5000;'); } catch(e) {}
try {
  const dCount = db.prepare('SELECT COUNT(*) as c FROM departments').get().c;
  if (dCount === 0) {
    db.prepare('INSERT INTO departments (department_id, name, created_at) VALUES (?, ?, ?)').run('DEPT-001', 'قسم النقل والآليات', new Date().toISOString());
    db.prepare('INSERT INTO departments (department_id, name, created_at) VALUES (?, ?, ?)').run('DEPT-002', 'قسم الصيانة والورش الفنية', new Date().toISOString());
    db.prepare('INSERT INTO departments (department_id, name, created_at) VALUES (?, ?, ?)').run('DEPT-003', 'قسم الحركة والمتابعة', new Date().toISOString());
  }
} catch(e) {}


db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  -- Users Table (Roles: USER, AUDITOR, ADMIN)
  CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    department TEXT NOT NULL,
    unit TEXT NOT NULL,
    fcm_token TEXT,
    role TEXT CHECK(role IN ('USER', 'AUDITOR', 'ADMIN', 'DEPARTMENT_HEAD')) DEFAULT 'USER',
    is_active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

  -- Maintenance Transactions Table (3-Tier Lifecycle)
  CREATE TABLE IF NOT EXISTS maintenance_transactions (
    transaction_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    vehicle_numbers TEXT NOT NULL,
    vehicle_images TEXT NOT NULL,
    receipt_images TEXT NOT NULL,
    category TEXT,
    status TEXT CHECK(status IN ('PENDING_AUDITOR', 'IN_PROGRESS', 'PENDING_ADMIN', 'AUDITED')) DEFAULT 'PENDING_AUDITOR',
    is_locked INTEGER NOT NULL DEFAULT 1,
    auditor_note TEXT,
    admin_note TEXT,
    submitted_at TEXT NOT NULL,
    audited_by_auditor_at TEXT,
    audited_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE RESTRICT
  );

  CREATE INDEX IF NOT EXISTS idx_submitted_at ON maintenance_transactions(submitted_at);
  CREATE INDEX IF NOT EXISTS idx_user_id ON maintenance_transactions(user_id);
  CREATE INDEX IF NOT EXISTS idx_status ON maintenance_transactions(status);

  -- Notifications Table
  CREATE TABLE IF NOT EXISTS notifications (
    notification_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    transaction_id TEXT,
    title TEXT NOT NULL,
    purpose TEXT,
    message TEXT NOT NULL,
    type TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
  );

  -- Maintenance Categories Table (إدارة أنواع الصيانة)
  CREATE TABLE IF NOT EXISTS maintenance_categories (
    category_id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    icon TEXT DEFAULT '🛞',
    description TEXT,
    created_at TEXT NOT NULL
  );

  -- System Settings Table (إعدادات النظام والتخصيص)
    -- Departments Table (إدارة الأقسام)
  CREATE TABLE IF NOT EXISTS departments (
    department_id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
  );

  -- Maintenance Requests Table (طلبات الصيانة الواردة)
  CREATE TABLE IF NOT EXISTS maintenance_requests (
    request_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    user_name TEXT,
    department TEXT,
    vehicle_number TEXT NOT NULL,
    current_km INTEGER NOT NULL,
    category TEXT NOT NULL,
    notes TEXT,
    status TEXT DEFAULT 'PENDING',
    workshop_name TEXT,
    admin_response_note TEXT,
    created_at TEXT NOT NULL,
    responded_at TEXT
  );

  CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  -- Login History Table (سجل تسجيلات الدخول)
  


  CREATE TABLE IF NOT EXISTS login_history (
    log_id TEXT PRIMARY KEY,
    user_id TEXT,
    username TEXT NOT NULL,
    full_name TEXT,
    role TEXT,
    ip_address TEXT,
    user_agent TEXT,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL
  );
`);

// ==============================================================================
// v3 Schema Migrations & Extensions
// ==============================================================================
try { db.prepare("ALTER TABLE maintenance_transactions ADD COLUMN current_km INTEGER DEFAULT 0").run(); } catch(e){}
try { db.prepare("ALTER TABLE maintenance_transactions ADD COLUMN maintenance_price REAL DEFAULT 0").run(); } catch(e){}
try { db.prepare("ALTER TABLE maintenance_transactions ADD COLUMN notes TEXT DEFAULT ''").run(); } catch(e){}
try { db.prepare("ALTER TABLE maintenance_transactions ADD COLUMN is_deleted INTEGER DEFAULT 0").run(); } catch(e){}
try { db.prepare("ALTER TABLE maintenance_transactions ADD COLUMN deleted_at TEXT").run(); } catch(e){}
try { db.prepare("ALTER TABLE maintenance_transactions ADD COLUMN deleted_by TEXT").run(); } catch(e){}

// Granular permissions & Department Manager migrations (v4/v7.2)
try { db.prepare("ALTER TABLE users ADD COLUMN can_add_transaction INTEGER DEFAULT 1").run(); } catch(e){}
try { db.prepare("ALTER TABLE users ADD COLUMN is_department_manager INTEGER DEFAULT 0").run(); } catch(e){}
try { db.prepare("ALTER TABLE users ADD COLUMN assigned_department_id TEXT DEFAULT ''").run(); } catch(e){}
try { db.prepare("ALTER TABLE users ADD COLUMN can_add_dept_members_transactions INTEGER DEFAULT 0").run(); } catch(e){}
try { db.prepare("ALTER TABLE users ADD COLUMN can_edit_dept_transactions INTEGER DEFAULT 0").run(); } catch(e){}
try { db.prepare("ALTER TABLE users ADD COLUMN is_read_only INTEGER DEFAULT 0").run(); } catch(e){}
try { db.prepare("ALTER TABLE users ADD COLUMN is_deleted INTEGER DEFAULT 0").run(); } catch(e){}
try { db.prepare("ALTER TABLE users ADD COLUMN deleted_at TEXT").run(); } catch(e){}
try { db.prepare("ALTER TABLE users ADD COLUMN deleted_by TEXT").run(); } catch(e){}

// Sync existing Department Head users to have department manager flags
try {
  db.prepare("UPDATE users SET is_department_manager = 1, can_add_dept_members_transactions = 1, can_edit_dept_transactions = 1 WHERE role = 'DEPARTMENT_HEAD' OR role = 'Department_Head'").run();
  db.prepare("UPDATE users SET assigned_department_id = department WHERE (assigned_department_id IS NULL OR assigned_department_id = '') AND department IS NOT NULL").run();
  db.prepare("UPDATE users SET can_add_transaction = 1 WHERE can_add_transaction IS NULL").run();
} catch(e) {}

// Transactions granular fields
try { db.prepare("ALTER TABLE maintenance_transactions ADD COLUMN department_id TEXT").run(); } catch(e){}
try { db.prepare("ALTER TABLE maintenance_transactions ADD COLUMN member_user_id TEXT").run(); } catch(e){}
try { db.prepare("ALTER TABLE maintenance_transactions ADD COLUMN created_by TEXT").run(); } catch(e){}
try { db.prepare("ALTER TABLE maintenance_transactions ADD COLUMN updated_by TEXT").run(); } catch(e){}

// Backfill transactions department_id and created_by if missing
try {
  db.prepare(`
    UPDATE maintenance_transactions
    SET department_id = (SELECT department FROM users WHERE users.user_id = maintenance_transactions.user_id),
        created_by = user_id
    WHERE department_id IS NULL OR department_id = ''
  `).run();
} catch(e) {}

// Departments soft delete fields
try { db.prepare("ALTER TABLE departments ADD COLUMN is_deleted INTEGER DEFAULT 0").run(); } catch(e){}
try { db.prepare("ALTER TABLE departments ADD COLUMN deleted_at TEXT").run(); } catch(e){}
try { db.prepare("ALTER TABLE departments ADD COLUMN deleted_by TEXT").run(); } catch(e){}

// Audit log helper function
function logAudit(action, entityType, entityId, actorId, actorName, details) {
  try {
    const id = 'AUDIT-' + crypto.randomUUID().slice(0, 8);
    const now = new Date().toISOString();
    const detailsStr = typeof details === 'object' ? JSON.stringify(details) : String(details || '');
    db.prepare(`
      INSERT INTO audit_logs (id, action, entity_type, entity_id, actor_id, actor_name, details, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, action, entityType, String(entityId || ''), String(actorId || 'system'), String(actorName || ''), detailsStr, now);
  } catch(e) {
    console.warn('logAudit warning:', e.message);
  }
}

db.exec(`
  CREATE TABLE IF NOT EXISTS vehicles (
    vehicle_id TEXT PRIMARY KEY,
    plate_number TEXT UNIQUE NOT NULL,
    department_id TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    deleted_at TEXT,
    deleted_by TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_vehicles_plate ON vehicles(plate_number);

  CREATE TABLE IF NOT EXISTS deleted_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    record_snapshot TEXT NOT NULL,
    deleted_by TEXT,
    deleted_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_del_rec_entity ON deleted_records(entity_type, entity_id);

  CREATE TABLE IF NOT EXISTS km_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id TEXT NOT NULL,
    old_km INTEGER,
    new_km INTEGER,
    admin_id TEXT,
    admin_name TEXT,
    timestamp TEXT NOT NULL,
    reason TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_km_audit_tx ON km_audit_logs(transaction_id);

  CREATE TABLE IF NOT EXISTS notification_read_receipts (
    id TEXT PRIMARY KEY,
    notification_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    user_name TEXT,
    seen_at TEXT NOT NULL,
    sync_status TEXT DEFAULT 'SYNCED',
    created_at TEXT NOT NULL,
    UNIQUE(notification_id, user_id)
  );
  CREATE INDEX IF NOT EXISTS idx_nrr_notif ON notification_read_receipts(notification_id);
  CREATE INDEX IF NOT EXISTS idx_nrr_user ON notification_read_receipts(user_id);

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    actor_id TEXT NOT NULL,
    actor_name TEXT,
    details TEXT,
    timestamp TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_logs(entity_type, entity_id);
  CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);

  CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT PRIMARY KEY,
    endpoint TEXT,
    response_code INTEGER,
    response_body TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_idemp_key ON idempotency_keys(key);
`);

try { db.prepare("ALTER TABLE maintenance_requests ADD COLUMN notes TEXT DEFAULT ''").run(); } catch(e){}

// Auto-sync all vehicles from transactions into vehicles table on startup
try {
  const txRows = db.prepare('SELECT t.vehicle_numbers, u.department FROM maintenance_transactions t LEFT JOIN users u ON t.user_id = u.user_id').all();
  const insertVeh = db.prepare('INSERT OR IGNORE INTO vehicles (vehicle_id, plate_number, department_id, is_active, is_deleted, created_at) VALUES (?, ?, ?, 1, 0, ?)');
  const now = new Date().toISOString();
  txRows.forEach(r => {
    let pList = [];
    try {
      pList = Array.isArray(r.vehicle_numbers) ? r.vehicle_numbers : JSON.parse(r.vehicle_numbers);
    } catch(e) {
      if (typeof r.vehicle_numbers === 'string') pList = [r.vehicle_numbers];
    }
    pList.forEach(p => {
      if (!p || !p.trim()) return;
      const plate = p.trim();
      const existing = db.prepare('SELECT vehicle_id FROM vehicles WHERE plate_number = ?').get(plate);
      if (!existing) {
        const vId = 'VEH-' + crypto.randomUUID().slice(0, 6);
        insertVeh.run(vId, plate, r.department || 'DEPT-001', now);
      }
    });
  });
} catch(e) {
  console.warn('Vehicle sync warning:', e);
}



// Seed Default Categories if empty
const catCount = db.prepare('SELECT COUNT(*) as count FROM maintenance_categories').get().count;
if (catCount === 0) {
  const defaultCats = [
    { id: 'CAT-01', name: 'تبديل إطارات (عجلات)', icon: '🛞', desc: 'تبديل إطارات شاحنات وسيارات خفيفة وتثبيت دوزان' },
    { id: 'CAT-02', name: 'صيانة ميكانيكية وميزانية', icon: '⚙️', desc: 'صيانة صدر أمامي وميزانية وتبطين درامات' },
    { id: 'CAT-03', name: 'تبديل زيوت وفلاتر', icon: '🛢️', desc: 'تبديل زيوت محرك وهيدروليك وفلاتر ديزل وهواء' },
    { id: 'CAT-04', name: 'شراء بطاريات جديدة', icon: '🔋', desc: 'تجهيز بطاريات شحن جافة وسائلة للآليات' },
    { id: 'CAT-05', name: 'صيانة كهربائية وتبريد', icon: '⚡', desc: 'فحص دينامو سلف وتعبئة غاز تبريد وفحص كهرباء' },
    { id: 'CAT-06', name: 'صيانة بوشات ونوابض', icon: '🔩', desc: 'تبديل بوشات قامات ونوابض خلفية للشاحنات' },
    { id: 'CAT-07', name: 'صيانة شاملة ومشتريات أخرى', icon: '🛠️', desc: 'مشتريات قطع غيار متفرقة وفحص سنوي' }
  ];
  const catStmt = db.prepare('INSERT INTO maintenance_categories (category_id, name, icon, description, created_at) VALUES (?, ?, ?, ?, ?)');
  const now = new Date().toISOString();
  for (const c of defaultCats) {
    catStmt.run(c.id, c.name, c.icon, c.desc, now);
  }
}

// Seed Default Settings if empty
const setCount = db.prepare('SELECT COUNT(*) as count FROM system_settings').get().count;
if (setCount === 0) {
  const defaultSettings = {
    app_name: 'صيانة العجلات',
    app_subtitle: 'منظومة إدارة وتوثيق مشتريات وصيانة العجلات (v2.0)',
    entity_name: 'إدارة الصيانة والآليات المركزية',
    app_icon: '🛞',
    theme_color: '#1d4ed8',
    notif_sound_enabled: '1',
    watermark_required: '1',
    auditor_required: '1'
  };
  const setStmt = db.prepare('INSERT INTO system_settings (key, value) VALUES (?, ?)');
  for (const [k, v] of Object.entries(defaultSettings)) {
    setStmt.run(k, v);
  }
}

// ------------------------------------------------------------------------------
// Seed Initial Demo Accounts
// ------------------------------------------------------------------------------
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;

if (userCount === 0) {
  console.log('Seeding initial secure administrator, receipt auditor, and field user accounts...');

  const adminId = 'USR-ADMIN-001';
  const auditorId = 'USR-AUDITOR-001';
  const fieldUserId = 'USR-FIELD-001';
  const now = new Date().toISOString();

  // 1. Admin (admin / admin123)
  db.prepare(`
    INSERT INTO users (user_id, username, password_hash, full_name, department, unit, fcm_token, role, is_active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'ADMIN', 1, ?)
  `).run(
    adminId,
    'admin',
    hashPassword('admin123'),
    'المهندس أحمد مصطفى (مدير الإدارة والتدقيق المركزي)',
    'إدارة الصيانة والآليات المركزية',
    'الرقابة المركزية والاعتماد المالي',
    'fcm-token-admin-root',
    now
  );

  // 2. Receipt Auditor (auditor1 / auditor123)
  db.prepare(`
    INSERT INTO users (user_id, username, password_hash, full_name, department, unit, fcm_token, role, is_active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'AUDITOR', 1, ?)
  `).run(
    auditorId,
    'auditor1',
    hashPassword('auditor123'),
    'الأستاذ سجاد حسين علي (مدقق وصولات معتمد)',
    'شعبة التدقيق المالي ومطابقة الفواتير',
    'لجنة فحص الوصولات وقوائم التجهيز',
    'fcm-token-auditor-001',
    now
  );

  // 3. Field User (user1 / 123456)
  db.prepare(`
    INSERT INTO users (user_id, username, password_hash, full_name, department, unit, fcm_token, role, is_active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'USER', 1, ?)
  `).run(
    fieldUserId,
    'user1',
    hashPassword('123456'),
    'حيدر علي عبد الحسين',
    'قسم النقل والحركة الميدانية',
    'شعبة العجلات الثقيلة',
    'fcm-token-field-001',
    now
  );

  const sampleVehicleImages = JSON.stringify([
    '/assets/sample-wheel-1.svg',
    '/assets/sample-wheel-2.svg'
  ]);
  const sampleReceiptImages = JSON.stringify([
    '/assets/sample-receipt-1.svg'
  ]);

  // Sample 1: PENDING_AUDITOR (Waiting for receipt auditor)
  db.prepare(`
    INSERT INTO maintenance_transactions (
      transaction_id, user_id, vehicle_numbers, vehicle_images, receipt_images,
      category, status, is_locked, auditor_note, admin_note, submitted_at, audited_by_auditor_at, audited_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_AUDITOR', 1, NULL, NULL, ?, NULL, NULL)
  `).run(
    'TX-2026-0118',
    fieldUserId,
    JSON.stringify(['بغداد 63901 / حمل']),
    sampleVehicleImages,
    sampleReceiptImages,
    'إطارات',
    new Date(Date.now() - 30 * 60000).toISOString()
  );

  // Sample 2: PENDING_ADMIN (Auditor approved, now waiting for Admin final approval)
  db.prepare(`
    INSERT INTO maintenance_transactions (
      transaction_id, user_id, vehicle_numbers, vehicle_images, receipt_images,
      category, status, is_locked, auditor_note, admin_note, submitted_at, audited_by_auditor_at, audited_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_ADMIN', 1, ?, NULL, ?, ?, NULL)
  `).run(
    'TX-2026-0104',
    fieldUserId,
    JSON.stringify(['البصرة 7543 / خصوصي']),
    sampleVehicleImages,
    sampleReceiptImages,
    'زيوت وفلاتر',
    'تم تدقيق وصولات الشراء ومطابقة الأسعار والأختام الرسمية مع قائمة المجهزين المعتمدين وجاهزة للاعتماد النهائي.',
    new Date(Date.now() - 5 * 3600000).toISOString(),
    new Date(Date.now() - 2 * 3600000).toISOString()
  );

  // Sample 3: AUDITED (Fully approved by Auditor and Admin)
  db.prepare(`
    INSERT INTO maintenance_transactions (
      transaction_id, user_id, vehicle_numbers, vehicle_images, receipt_images,
      category, status, is_locked, auditor_note, admin_note, submitted_at, audited_by_auditor_at, audited_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'AUDITED', 1, ?, ?, ?, ?, ?)
  `).run(
    'TX-2026-0091',
    fieldUserId,
    JSON.stringify(['بغداد 48210 / نقل', 'بغداد 19302 / حمل']),
    sampleVehicleImages,
    sampleReceiptImages,
    'إطارات',
    'تم فحص وصل القبض ومطابقة أسعار إطارات الشاحنات والتأكد من أختام الشركة المجهزة.',
    'تم مطابقة الفاتورة مع فحص السلامة الميداني والاعتماد المالي النهائي والصرف.',
    new Date(Date.now() - 2 * 86400000).toISOString(),
    new Date(Date.now() - 86400000).toISOString(),
    new Date(Date.now() - 43200000).toISOString()
  );
}

// ------------------------------------------------------------------------------
// SSE Broadcast for Real-Time Push Notifications
// ------------------------------------------------------------------------------
const sseClients = new Set();

function broadcastEvent(type, payload) {
  const data = JSON.stringify({ type, payload, timestamp: new Date().toISOString() });
  for (const res of sseClients) {
    try {
      res.write(`data: ${data}\n\n`);
    } catch (e) {
      sseClients.delete(res);
    }
  }
}

// Helper: Check and trigger Periodic Inspection / Overdue alerts (Task 6)
function checkAndTriggerOverdueAlerts(plateNumber, currentKm, transactionId = null) {
  if (!plateNumber || !currentKm || currentKm <= 0) return [];
  try {
    const trimmedPlate = String(plateNumber).trim();
    const v = db.prepare('SELECT * FROM vehicles WHERE plate_number = ?').get(trimmedPlate);
    const vehDept = v ? v.department_id : null;

    const categories = db.prepare('SELECT * FROM maintenance_categories').all();
    const prevTxs = db.prepare(`
      SELECT category, current_km
      FROM maintenance_transactions
      WHERE vehicle_numbers LIKE ? AND (is_deleted = 0 OR is_deleted IS NULL)
    `).all(`%${trimmedPlate}%`);

    const overdueAlerts = [];
    const now = new Date().toISOString();

    for (const cat of categories) {
      const typeName = cat.name;
      const defaultKm = parseInt(cat.default_replacement_km, 10) || 5000;

      let lastKm = 0;
      for (const t of prevTxs) {
        if (t.category === typeName && (t.current_km || 0) > lastKm) {
          lastKm = t.current_km;
        }
      }

      let dueKm = 0;
      if (lastKm > 0) {
        dueKm = lastKm + defaultKm;
      } else if (prevTxs.length > 0) {
        const maxKm = Math.max(...prevTxs.map(t => t.current_km || 0));
        if (maxKm > 0) dueKm = maxKm + defaultKm;
      }

      if (dueKm > 0 && currentKm > dueKm) {
        const alertMsg = `تنبيه فحص دوري: العجلة رقم [${trimmedPlate}] - يرجى تفقد صيانة [${typeName}] كونها تجاوزت المدة الافتراضية للتبديل.`;
        overdueAlerts.push({ plate: trimmedPlate, category: typeName, currentKm, dueKm, message: alertMsg });

        // 1. Notify all ADMIN users
        const admins = db.prepare("SELECT user_id FROM users WHERE role = 'ADMIN' OR LOWER(username) = 'admin'").all();
        for (const a of admins) {
          const notifId = 'NOTIF-OVERDUE-' + crypto.randomUUID().slice(0, 8);
          db.prepare(`
            INSERT INTO notifications (notification_id, user_id, transaction_id, title, purpose, message, type, is_read, created_at)
            VALUES (?, ?, ?, '🚨 تنبيه فحص دوري عاجل', 'تجاوز الكيلومترات الافتراضية', ?, 'OVERDUE', 0, ?)
          `).run(notifId, a.user_id, transactionId, alertMsg, now);
        }

        // 2. Automated Routing to matching Department Head:
        if (vehDept) {
          const deptHeads = db.prepare(`
            SELECT user_id FROM users
            WHERE (role = 'DEPARTMENT_HEAD' OR role = 'Department_Head')
              AND (department = ? OR department IN (SELECT name FROM departments WHERE department_id = ?) OR department IN (SELECT department_id FROM departments WHERE name = ?))
          `).all(vehDept, vehDept, vehDept);

          for (const dh of deptHeads) {
            const notifId = 'NOTIF-OVERDUE-' + crypto.randomUUID().slice(0, 8);
            db.prepare(`
              INSERT INTO notifications (notification_id, user_id, transaction_id, title, purpose, message, type, is_read, created_at)
              VALUES (?, ?, ?, '🚨 تنبيه فحص دوري لعجلات قسمك', 'تجاوز الكيلومترات الافتراضية', ?, 'OVERDUE', 0, ?)
            `).run(notifId, dh.user_id, transactionId, alertMsg, now);
          }
        }

        // 3. Broadcast live event to all connected clients
        broadcastEvent('PERIODIC_INSPECTION_ALERT', {
          vehicle_number: trimmedPlate,
          category: typeName,
          current_km: currentKm,
          due_km: dueKm,
          department_id: vehDept,
          message: alertMsg,
          sound: 'default'
        });
      }
    }
    return overdueAlerts;
  } catch (err) {
    console.error('Error in checkAndTriggerOverdueAlerts:', err);
    return [];
  }
}

// ------------------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------------------
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 50 * 1024 * 1024) {
        reject(new Error('Payload Too Large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data) {
  const payload = JSON.stringify(data);
  if (res && res._idempotencyKey && statusCode >= 200 && statusCode < 300) {
    try {
      db.prepare(`
        INSERT OR REPLACE INTO idempotency_keys (key, endpoint, response_code, response_body, created_at)
        VALUES (?, ?, ?, ?, datetime('now'))
      `).run(res._idempotencyKey, res._reqPath || '', statusCode, payload);
    } catch (e) {}
  }
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-Idempotency-Key, x-idempotency-key, x-user-role, x-role',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  });
  res.end(payload);
}

// ------------------------------------------------------------------------------
// Advanced Security Firewall: Anti-DDoS, Brute Force Protection & IP Rate Limiting
// ------------------------------------------------------------------------------
const ipFirewallMap = new Map();

function checkFirewallProtection(req, res, isLogin = false) {
  const ip = req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();
  let record = ipFirewallMap.get(ip);
  if (!record) {
    record = { reqCount: 0, resetTime: now + 60000, failedLogins: 0, lockedUntil: 0 };
    ipFirewallMap.set(ip, record);
  }

  // 1. Check if IP was temporarily banned by Firewall for repeated failed attacks
  if (record.lockedUntil > now) {
    const mins = Math.ceil((record.lockedUntil - now) / 60000);
    sendJson(res, 429, {
      error: `تم حظر هذا الاتصال مؤقتاً بواسطة جدار الحماية الأمني (Firewall) لمدة ${mins} دقيقة بسبب تكرار المحاولات المشبوهة.`,
      firewall_active: true,
      retry_after_minutes: mins
    });
    return false;
  }

  // 2. High-volume Rate Limiting (max 150 req/min per IP)
  if (now > record.resetTime) {
    record.reqCount = 0;
    record.resetTime = now + 60000;
  }
  record.reqCount++;

  if (record.reqCount > 150 && !isLogin) {
    sendJson(res, 429, {
      error: 'تجاوزت الحد المسموح من الطلبات السريعة في الدقيقة. جدار الحماية يحمي النظام من الإغراق.',
      firewall_active: true
    });
    return false;
  }

  return true;
}

function handleFailedLoginAttempt(ip) {
  const now = Date.now();
  let record = ipFirewallMap.get(ip);
  if (!record) {
    record = { reqCount: 0, resetTime: now + 60000, failedLogins: 0, lockedUntil: 0 };
    ipFirewallMap.set(ip, record);
  }
  record.failedLogins++;
  // Lock after 5 consecutive failed attempts
  if (record.failedLogins >= 5) {
    record.lockedUntil = now + (15 * 60 * 1000); // 15 mins lockdown
  }
}

function handleSuccessfulLoginAttempt(ip) {
  let record = ipFirewallMap.get(ip);
  if (record) {
    record.failedLogins = 0;
    record.lockedUntil = 0;
  }
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip',
  '.apk': 'application/vnd.android.package-archive'
};

function serveStatic(req, res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(err.code === 'ENOENT' ? 404 : 500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('File Not Found');
    } else {
      res.writeHead(200, {
        'Content-Type': contentType,
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN'
      });
      res.end(content);
    }
  });
}

// ------------------------------------------------------------------------------
// HTTP Server
// ------------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-Idempotency-Key, x-idempotency-key, x-user-role, x-role',
      'X-Content-Type-Options': 'nosniff'
    });
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // Enforce Firewall Protection
  if (!checkFirewallProtection(req, res, pathname === '/api/login')) {
    return;
  }

  const idempKey = (req.headers['x-idempotency-key'] || req.headers['X-Idempotency-Key'] || '').toString().trim();
  if (idempKey && req.method !== 'GET' && req.method !== 'OPTIONS') {
    const cached = db.prepare('SELECT response_code, response_body FROM idempotency_keys WHERE key = ?').get(idempKey);
    if (cached) {
      res.writeHead(cached.response_code, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'X-Idempotency-Hit': 'true'
      });
      return res.end(cached.response_body);
    }
    res._idempotencyKey = idempKey;
    res._reqPath = pathname;
  }

  // SSE Stream
  if (pathname === '/api/events' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });
    res.write(': connected\n\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  try {
    // --------------------------------------------------------------------------
    // 0. API Health & Firewall Status (Ping)
    // --------------------------------------------------------------------------
    if ((pathname === '/api/ping' || pathname === '/api/health') && req.method === 'GET') {
      let cloudUrl = null;
      try {
        const p = path.join(__dirname, 'public', 'cloud_url.json');
        if (fs.existsSync(p)) {
          cloudUrl = JSON.parse(fs.readFileSync(p, 'utf-8')).url;
        }
      } catch (e) {}

      return sendJson(res, 200, {
        status: 'ok',
        system: 'نظام صيانة العجلات والمشتريات المركزي',
        firewall: 'Active (Protected by Rate Limiter & Audit Locks)',
        timestamp: new Date().toISOString(),
        cloud_url: cloudUrl,
        local_network_ip: '192.168.0.104:3000',
        version: '2.0.0'
      });
    }

    // --------------------------------------------------------------------------
    // 0.1 Full Cloud Sync Endpoint (GET /api/sync)
    // --------------------------------------------------------------------------
    if (pathname === '/api/sync' && req.method === 'GET') {
      const role = (parsedUrl.searchParams.get('role') || '').toUpperCase();
      const isAdmin = role === 'ADMIN';

      const rows = db.prepare(`
        SELECT t.*, u.full_name as user_name, u.department, u.unit, u.fcm_token, u.username
        FROM maintenance_transactions t
        LEFT JOIN users u ON t.user_id = u.user_id
        WHERE (t.is_deleted = 0 OR t.is_deleted IS NULL)
        ORDER BY datetime(t.submitted_at) DESC
      `).all();

      const formattedTxs = rows.map(r => {
        const item = {
          ...r,
          vehicle_numbers: JSON.parse(r.vehicle_numbers || '[]'),
          vehicle_images: JSON.parse(r.vehicle_images || '[]'),
          receipt_images: JSON.parse(r.receipt_images || '[]'),
          current_km: r.current_km || 0,
          maintenance_price: isAdmin ? (parseFloat(r.maintenance_price) || 0) : 0,
          notes: r.notes || '',
          is_locked: Boolean(r.is_locked)
        };
        if (!isAdmin) {
          delete item.maintenance_price;
        }
        return item;
      });

      const categories = db.prepare('SELECT * FROM maintenance_categories').all();
      const departments = db.prepare('SELECT * FROM departments WHERE (is_deleted = 0 OR is_deleted IS NULL) ORDER BY name ASC').all();
      const requests = db.prepare('SELECT * FROM maintenance_requests ORDER BY datetime(created_at) DESC LIMIT 100').all();
      const settingRows = db.prepare('SELECT key, value FROM system_settings').all();
      const settings = {};
      settingRows.forEach(r => { settings[r.key] = r.value; });
      const notifications = db.prepare('SELECT * FROM notifications ORDER BY datetime(created_at) DESC LIMIT 30').all();
      const users = db.prepare(`
        SELECT user_id, username, full_name, department, unit, role, is_active,
               can_add_transaction, is_department_manager, assigned_department_id,
               can_add_dept_members_transactions, can_edit_dept_transactions, is_read_only,
               is_deleted, created_at
        FROM users
        WHERE (is_deleted = 0 OR is_deleted IS NULL)
      `).all();
      const vehicles = db.prepare('SELECT * FROM vehicles WHERE (is_deleted = 0 OR is_deleted IS NULL) ORDER BY plate_number ASC').all();
      const deletedRecords = isAdmin ? db.prepare('SELECT * FROM deleted_records ORDER BY datetime(deleted_at) DESC LIMIT 100').all() : [];
      const readReceipts = db.prepare('SELECT * FROM notification_read_receipts ORDER BY datetime(seen_at) DESC LIMIT 200').all();
      const auditLogs = isAdmin ? db.prepare('SELECT * FROM audit_logs ORDER BY datetime(timestamp) DESC LIMIT 100').all() : [];

      return sendJson(res, 200, {
        success: true,
        server_time: new Date().toISOString(),
        transactions: formattedTxs,
        categories: categories,
        departments: departments,
        maintenance_requests: requests,
        settings: settings,
        notifications: notifications,
        users: users,
        vehicles: vehicles,
        deleted_records: deletedRecords,
        read_receipts: readReceipts,
        audit_logs: auditLogs
      });
    }

    // --------------------------------------------------------------------------
    // 0.2 Push Offline Transactions (POST /api/sync/push)
    // --------------------------------------------------------------------------
    if (pathname === '/api/sync/push' && req.method === 'POST') {
      const body = await parseBody(req);
      const { items } = body;

      if (!Array.isArray(items)) {
        return sendJson(res, 400, { error: 'قائمة المعاملات غير صالحة' });
      }

      let insertedCount = 0;
      let updatedCount = 0;

      for (const item of items) {
        if (!item.transaction_id) continue;
        const existing = db.prepare('SELECT transaction_id, status FROM maintenance_transactions WHERE transaction_id = ?').get(item.transaction_id);

        if (!existing) {
          let syncUserId = item.user_id || 'user1';
          const userChk = db.prepare('SELECT user_id FROM users WHERE user_id = ? OR username = ?').get(syncUserId, syncUserId);
          if (userChk) {
            syncUserId = userChk.user_id;
          } else {
            const anyAdmin = db.prepare("SELECT user_id FROM users WHERE role = 'ADMIN' LIMIT 1").get();
            syncUserId = anyAdmin ? anyAdmin.user_id : 'USR-ADMIN-001';
          }

          const userDept = userChk ? userChk.department : (item.department_id || null);
          const stmt = db.prepare(`
            INSERT INTO maintenance_transactions (
              transaction_id, user_id, vehicle_numbers, vehicle_images, receipt_images,
              category, status, is_locked, auditor_note, admin_note, current_km, maintenance_price, notes, is_deleted,
              submitted_at, audited_by_auditor_at, audited_at, department_id, member_user_id, created_by, updated_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)
          `);

          stmt.run(
            item.transaction_id,
            syncUserId,
            JSON.stringify(item.vehicle_numbers || []),
            JSON.stringify(item.vehicle_images || []),
            JSON.stringify(item.receipt_images || []),
            item.category || 'صيانة عامة',
            item.status || 'PENDING_AUDITOR',
            item.is_locked ? 1 : 1,
            item.auditor_note || null,
            item.admin_note || null,
            parseInt(item.current_km, 10) || 0,
            parseFloat(item.maintenance_price || item.cost || 0) || 0,
            item.notes || '',
            item.submitted_at || new Date().toISOString(),
            item.audited_by_auditor_at || null,
            item.audited_at || null,
            item.department_id || userDept,
            item.member_user_id || null,
            item.created_by || syncUserId,
            item.updated_by || null
          );
          insertedCount++;
        } else {
          // If status updated
          if (item.status && item.status !== existing.status) {
            db.prepare(`
              UPDATE maintenance_transactions
              SET status = ?, auditor_note = COALESCE(?, auditor_note), admin_note = COALESCE(?, admin_note),
                  audited_by_auditor_at = COALESCE(?, audited_by_auditor_at), audited_at = COALESCE(?, audited_at),
                  updated_by = COALESCE(?, updated_by)
              WHERE transaction_id = ?
            `).run(item.status, item.auditor_note, item.admin_note, item.audited_by_auditor_at, item.audited_at, item.updated_by || null, item.transaction_id);
            updatedCount++;
          }
        }
      }

      // Sync offline read receipts if provided
      let receiptsSynced = 0;
      if (Array.isArray(body.read_receipts)) {
        const rcStmt = db.prepare(`
          INSERT OR REPLACE INTO notification_read_receipts (id, notification_id, user_id, user_name, seen_at, sync_status, created_at)
          VALUES (?, ?, ?, ?, ?, 'SYNCED', ?)
        `);
        for (const rc of body.read_receipts) {
          if (rc && rc.notification_id && rc.user_id) {
            const rId = rc.id || ('NRR-' + crypto.randomUUID().slice(0, 8));
            rcStmt.run(rId, rc.notification_id, rc.user_id, rc.user_name || '', rc.seen_at || new Date().toISOString(), rc.created_at || new Date().toISOString());
            receiptsSynced++;
          }
        }
      }

      if (insertedCount > 0 || updatedCount > 0) {
        broadcastEvent('SYNC_UPDATE', { inserted: insertedCount, updated: updatedCount });
      }

      return sendJson(res, 200, {
        success: true,
        message: `تمت المزامنة بنجاح: إدراج ${insertedCount} وتحديث ${updatedCount}`,
        inserted: insertedCount,
        updated: updatedCount
      });
    }

    // --------------------------------------------------------------------------
    // 1. Authentication (Login)
    // --------------------------------------------------------------------------
    if ((pathname === '/api/login' || pathname === '/api/auth/login') && req.method === 'POST') {
      const body = await parseBody(req);
      const { username, password } = body;
      const ip = req.socket.remoteAddress || '127.0.0.1';
      const userAgent = req.headers['user-agent'] || 'Unknown Device';
      const now = new Date().toISOString();

      if (!username || !password) {
        return sendJson(res, 400, { error: 'يرجى إدخال اسم المستخدم وكلمة المرور' });
      }

      const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username.trim());

      const logStmt = db.prepare(`
        INSERT INTO login_history (log_id, user_id, username, full_name, role, ip_address, user_agent, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      if (!user) {
        handleFailedLoginAttempt(ip);
        logStmt.run('LOG-' + crypto.randomUUID().slice(0, 8), null, username.trim(), null, null, ip, userAgent, 'FAILED_USER_NOT_FOUND', now);
        return sendJson(res, 401, { error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
      }

      if (user.is_active !== 1) {
        handleFailedLoginAttempt(ip);
        logStmt.run('LOG-' + crypto.randomUUID().slice(0, 8), user.user_id, user.username, user.full_name, user.role, ip, userAgent, 'FAILED_SUSPENDED', now);
        return sendJson(res, 403, { error: 'هذا الحساب مجمد حالياً من قبل الإدارة' });
      }

      if (!verifyPassword(password, user.password_hash)) {
        handleFailedLoginAttempt(ip);
        logStmt.run('LOG-' + crypto.randomUUID().slice(0, 8), user.user_id, user.username, user.full_name, user.role, ip, userAgent, 'FAILED_WRONG_PASSWORD', now);
        return sendJson(res, 401, { error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
      }

      // Successful login
      handleSuccessfulLoginAttempt(ip);
      logStmt.run('LOG-' + crypto.randomUUID().slice(0, 8), user.user_id, user.username, user.full_name, user.role, ip, userAgent, 'SUCCESS', now);

      const safeUser = {
        user_id: user.user_id,
        username: user.username,
        full_name: user.full_name,
        department: user.department,
        unit: user.unit,
        role: user.role,
        fcm_token: user.fcm_token
      };

      return sendJson(res, 200, {
        success: true,
        message: 'تم تسجيل الدخول بنجاح',
        user: safeUser,
        token: 'auth_' + crypto.randomUUID()
      });
    }

    if ((pathname === '/api/auth/me' || pathname === '/api/me') && req.method === 'GET') {
      const authHeader = req.headers['authorization'] || '';
      const userId = (req.headers['x-user-id'] || parsedUrl.searchParams.get('user_id') || '').toString().trim();
      let user = null;
      if (userId) {
        user = db.prepare('SELECT user_id, username, full_name, department, unit, role, is_active FROM users WHERE user_id = ? OR LOWER(username) = LOWER(?)').get(userId, userId);
      } else {
        user = db.prepare('SELECT user_id, username, full_name, department, unit, role, is_active FROM users WHERE is_active = 1 LIMIT 1').get();
      }
      if (!user) {
        return sendJson(res, 401, { success: false, error: 'غير مصرح أو المستخدم غير موجود' });
      }
      return sendJson(res, 200, { success: true, user });
    }


    // --------------------------------------------------------------------------
    // 1.1 Change Password for Logged-In User (المطلب 10)
    // --------------------------------------------------------------------------
    if (pathname === '/api/user/change-password' && req.method === 'POST') {
      const body = await parseBody(req);
      const { user_id, current_password, new_password } = body;

      if (!user_id || !current_password || !new_password) {
        return sendJson(res, 400, { error: 'يرجى إدخال كلمة المرور الحالية والجديدة' });
      }
      if (new_password.trim().length < 3) {
        return sendJson(res, 400, { error: 'يجب أن لا تقل كلمة المرور الجديدة عن 3 خانات' });
      }

      const user = db.prepare('SELECT * FROM users WHERE user_id = ?').get(user_id);
      if (!user) return sendJson(res, 404, { error: 'المستخدم غير موجود' });

      if (!verifyPassword(current_password, user.password_hash)) {
        return sendJson(res, 400, { error: 'كلمة المرور الحالية غير صحيحة' });
      }

      const newHash = hashPassword(new_password.trim());
      db.prepare('UPDATE users SET password_hash = ? WHERE user_id = ?').run(newHash, user_id);

      return sendJson(res, 200, { success: true, message: 'تم تغيير كلمة المرور بنجاح' });
    }

    // --------------------------------------------------------------------------
    // 1.2 Categories Management (المطلب 5)
    // --------------------------------------------------------------------------
    
    // --------------------------------------------------------------------------
    // 0.3 Departments CRUD Endpoints
    // --------------------------------------------------------------------------
    if (pathname === '/api/departments' && req.method === 'GET') {
      const rows = db.prepare('SELECT * FROM departments ORDER BY name ASC').all();
      return sendJson(res, 200, { departments: rows });
    }

    if ((pathname === '/api/admin/departments' || pathname === '/api/departments') && req.method === 'POST') {
      const body = await parseBody(req);
      const { name } = body;
      if (!name || !name.trim()) return sendJson(res, 400, { error: 'اسم القسم مطلوب' });
      const deptId = 'DEPT-' + crypto.randomUUID().slice(0, 8);
      try {
        db.prepare('INSERT INTO departments (department_id, name, created_at) VALUES (?, ?, ?)').run(deptId, name.trim(), new Date().toISOString());
        const rows = db.prepare('SELECT * FROM departments ORDER BY name ASC').all();
        broadcastEvent('DEPARTMENTS_UPDATED', { departments: rows });
        return sendJson(res, 201, { success: true, departments: rows });
      } catch (err) {
        return sendJson(res, 400, { error: 'اسم القسم موجود مسبقاً أو غير صالح' });
      }
    }

if ((pathname.match(/^\/api\/admin\/departments\/[A-Za-z0-9_-]+$/) || pathname.match(/^\/api\/departments\/[A-Za-z0-9_-]+$/)) && (req.method === 'PUT' || req.method === 'PATCH')) {
      const deptId = pathname.split('/').pop();
      const body = await parseBody(req);
      const { name } = body;
      if (!name || !name.trim()) return sendJson(res, 400, { error: 'اسم القسم مطلوب' });
      const newName = name.trim();

      const dept = db.prepare('SELECT * FROM departments WHERE department_id = ?').get(deptId);
      if (!dept) return sendJson(res, 404, { error: 'القسم غير موجود' });

      const existing = db.prepare('SELECT department_id FROM departments WHERE name = ? AND department_id != ?').get(newName, deptId);
      if (existing) return sendJson(res, 400, { error: 'يوجد قسم آخر بنفس هذا الاسم' });

      const oldName = dept.name;

      // Relational Integrity: update departments, users, vehicles, maintenance_requests
      db.prepare('UPDATE departments SET name = ? WHERE department_id = ?').run(newName, deptId);
      db.prepare('UPDATE users SET department = ? WHERE department = ? OR department = ?').run(newName, oldName, deptId);
      db.prepare('UPDATE vehicles SET department_id = ? WHERE department_id = ? OR department_id = ?').run(deptId, oldName, deptId);
      db.prepare('UPDATE maintenance_requests SET department = ? WHERE department = ? OR department = ?').run(newName, oldName, deptId);

      const rows = db.prepare('SELECT * FROM departments ORDER BY name ASC').all();
      broadcastEvent('DEPARTMENTS_UPDATED', { departments: rows });
      return sendJson(res, 200, { success: true, message: 'تم تعديل اسم القسم وتحديث كافة السجلات المرتبطة به بنجاح', departments: rows });
    }

    const isDeptDelete = (pathname === '/api/admin/departments/delete' && req.method === 'POST') ||
      (pathname.match(/^\/api\/admin\/departments\/[A-Za-z0-9_-]+$/) && req.method === 'DELETE');

    if (isDeptDelete) {
      let deptId = '';
      if (req.method === 'POST') {
        let body = {};
        try { body = await parseBody(req); } catch(e) {}
        deptId = body.department_id || body.id || body.name;
      } else {
        deptId = pathname.split('/').pop();
      }

      if (!deptId) return sendJson(res, 400, { error: 'معرف القسم مطلوب للحذف' });

      const existingDept = db.prepare('SELECT * FROM departments WHERE department_id = ? OR name = ?').get(deptId, deptId);
      if (!existingDept) return sendJson(res, 404, { error: 'القسم المطلوب حذفه غير موجود' });

      // Referential integrity check: check linked vehicles & users
      const vehCount = db.prepare('SELECT COUNT(*) as cnt FROM vehicles WHERE (department_id = ? OR department_id = ?) AND is_deleted = 0').get(existingDept.department_id, existingDept.name);
      const userCount = db.prepare('SELECT COUNT(*) as cnt FROM users WHERE (department = ? OR department = ?) AND is_active = 1').get(existingDept.department_id, existingDept.name);
      if ((vehCount && vehCount.cnt > 0) || (userCount && userCount.cnt > 0)) {
        return sendJson(res, 400, {
          error: `لا يمكن حذف قسم (${existingDept.name}) لوجود (${vehCount ? vehCount.cnt : 0}) عجلات و (${userCount ? userCount.cnt : 0}) مستخدمين نشطين مرتبطين به. يرجى نقلهم أولاً أو تعطيل القسم.`
        });
      }

      // Snapshot to deleted_records
      try {
        db.prepare(`
          INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by, deleted_at)
          VALUES ('department', ?, ?, 'admin', ?)
        `).run(existingDept.department_id, JSON.stringify(existingDept), new Date().toISOString());
      } catch(snapErr) {}

      db.prepare('DELETE FROM departments WHERE department_id = ?').run(existingDept.department_id);
      const rows = db.prepare('SELECT * FROM departments ORDER BY name ASC').all();
      broadcastEvent('DEPARTMENTS_UPDATED', { departments: rows });
      return sendJson(res, 200, { success: true, message: `تم حذف قسم (${existingDept.name}) بنجاح`, departments: rows });
    }

    // --------------------------------------------------------------------------
    // 0.4 Maintenance Requests (طلب صيانة) Endpoints
    // --------------------------------------------------------------------------
    if (pathname === '/api/maintenance-requests' && req.method === 'GET') {
      const userId = parsedUrl.searchParams.get('user_id');
      const dept = parsedUrl.searchParams.get('department');
      let query = 'SELECT * FROM maintenance_requests WHERE 1=1';
      const params = [];
      if (userId) { query += ' AND user_id = ?'; params.push(userId); }
      if (dept) { query += ' AND department = ?'; params.push(dept); }
      query += ' ORDER BY datetime(created_at) DESC';
      const rows = db.prepare(query).all(...params);
      return sendJson(res, 200, { requests: rows });
    }

    if (pathname === '/api/maintenance-requests' && req.method === 'POST') {
      const body = await parseBody(req);
      const { user_id, user_name, department, vehicle_number, current_km, category, notes } = body;

      if (!vehicle_number || current_km === undefined || !category) {
        return sendJson(res, 400, { error: 'رقم العجلة، قراءة العداد (كم)، ونوع الصيانة حقول مطلوبة' });
      }

      // Feature 3 & Task 4: Strict vehicle active/deleted and department isolation validation
      const v = db.prepare('SELECT * FROM vehicles WHERE plate_number = ?').get(vehicle_number.trim());
      if (v && (v.is_active === 0 || v.is_deleted === 1)) {
        return sendJson(res, 400, { error: 'لا يمكن إضافة صيانة لهذه العجلة لأنها معطلة أو محذوفة' });
      }

      // Strict department verification for non-admin
      const requesterUser = user_id ? db.prepare('SELECT * FROM users WHERE user_id = ? OR LOWER(username) = LOWER(?)').get(user_id, user_id) : null;
      if (requesterUser && requesterUser.role !== 'ADMIN') {
        if (!v) {
          return sendJson(res, 403, { error: 'لا يمكنك تسجيل معاملة لعجلة غير تابعة لقسمك' });
        }
        const userDept = requesterUser.department;
        const vehDept = v.department_id;
        const match = (
          vehDept === userDept ||
          db.prepare('SELECT 1 FROM departments WHERE (department_id = ? AND name = ?) OR (department_id = ? AND name = ?)').get(vehDept, userDept, userDept, vehDept)
        );
        if (!match) {
          return sendJson(res, 403, { error: 'لا يمكنك تسجيل معاملة لعجلة غير تابعة لقسمك' });
        }
      }

      const reqId = 'REQ-' + new Date().getFullYear() + '-' + Math.floor(1000 + Math.random() * 9000);
      const now = new Date().toISOString();
      const numKm = parseInt(current_km, 10) || 0;

      db.prepare(`
        INSERT INTO maintenance_requests (
          request_id, user_id, user_name, department, vehicle_number, current_km, category, notes, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
      `).run(reqId, user_id || 'user1', user_name || '', department || '', vehicle_number.trim(), numKm, category, notes || '', now);

      const adminUser = db.prepare("SELECT user_id FROM users WHERE role = 'ADMIN' OR LOWER(username) = 'admin' LIMIT 1").get();
      const targetAdminId = adminUser ? adminUser.user_id : 'USR-ADMIN-001';

      const notifId = 'NOTIF-' + crypto.randomUUID().slice(0, 8);
      db.prepare(`
        INSERT INTO notifications (notification_id, user_id, transaction_id, title, purpose, message, type, is_read, created_at)
        VALUES (?, ?, ?, 'طلب صيانة وارد جديد 🛠️', 'طلب صيانة من الميدان', ?, 'REQUEST', 0, ?)
      `).run(notifId, targetAdminId, reqId, `طلب صيانة للعجلة ${vehicle_number} (${category}) - قراءة العداد: ${numKm} كم`, now);

      broadcastEvent('NEW_MAINTENANCE_REQUEST', { request_id: reqId, vehicle_number, category, current_km: numKm, sound: 'default' });

      // Trigger periodic inspection / overdue check (Task 6)
      if (numKm > 0) {
        checkAndTriggerOverdueAlerts(vehicle_number.trim(), numKm, reqId);
      }
      return sendJson(res, 201, { success: true, message: 'تم إرسال طلب الصيانة بنجاح إلى الإدارة', request_id: reqId });
    }

    if (pathname === '/api/admin/maintenance-requests/respond' && req.method === 'POST') {
      const body = await parseBody(req);
      const { request_id, status, workshop_name, admin_response_note, role } = body;

      // Task 7: Department Head is strictly view/monitor only
      const callerRole = (role || parsedUrl.searchParams.get('role') || '').toUpperCase();
      if (callerRole === 'DEPARTMENT_HEAD') {
        return sendJson(res, 403, { error: 'غير مصرح: مسؤول القسم للمعاينة والمتابعة فقط ولا يملك صلاحية الرد على طلبات الصيانة' });
      }
      if (!request_id || !status) return sendJson(res, 400, { error: 'بيانات غير مكتملة' });
      const now = new Date().toISOString();

      db.prepare(`
        UPDATE maintenance_requests
        SET status = ?, workshop_name = ?, admin_response_note = ?, responded_at = ?
        WHERE request_id = ?
      `).run(status, workshop_name || null, admin_response_note || null, now, request_id);

      const reqRow = db.prepare('SELECT * FROM maintenance_requests WHERE request_id = ?').get(request_id);
      if (reqRow) {
        const title = status === 'AVAILABLE' ? '✅ تم قبول طلب الصيانة (متوفر)' : '❌ طلب الصيانة (غير متوفر)';
        const msg = status === 'AVAILABLE'
          ? `تمت الموافقة على صيانة العجلة ${reqRow.vehicle_number} (${reqRow.category}). يرجى التوجه إلى ورشة: [${workshop_name || 'الورشة المركزية'}].`
          : `نعتذر، الصيانة المطلوبة (${reqRow.category}) للعجلة ${reqRow.vehicle_number} غير متوفرة حالياً. ${admin_response_note || ''}`;

        const recipientUser = db.prepare('SELECT user_id FROM users WHERE user_id = ? OR LOWER(username) = LOWER(?) LIMIT 1').get(reqRow.user_id, reqRow.user_id);
        const validUserId = recipientUser ? recipientUser.user_id : 'USR-FIELD-001';

        const notifId = 'NOTIF-' + crypto.randomUUID().slice(0, 8);
        db.prepare(`
          INSERT INTO notifications (notification_id, user_id, transaction_id, title, purpose, message, type, is_read, created_at)
          VALUES (?, ?, ?, ?, 'رد الإدارة على طلب الصيانة', ?, 'RESPONSE', 0, ?)
        `).run(notifId, validUserId, request_id, title, msg, now);

        broadcastEvent('REQUEST_RESPONDED', { request_id, user_id: reqRow.user_id, status, workshop_name, message: msg, sound: 'default' });
      }
      return sendJson(res, 200, { success: true, message: 'تم حفظ رد الإدارة وإرسال الإشعار بنجاح' });
    }

    // --------------------------------------------------------------------------
    // 0.5 Fleet Vehicles Summary & Due Report
    // --------------------------------------------------------------------------
    if (pathname === '/api/vehicles/fleet-summary' && req.method === 'GET') {
      const transactions = db.prepare(`
        SELECT t.*, u.department, u.full_name as user_name
        FROM maintenance_transactions t LEFT JOIN users u ON t.user_id = u.user_id
        WHERE (t.is_deleted = 0 OR t.is_deleted IS NULL)
        ORDER BY datetime(t.submitted_at) DESC
      `).all();

      const categories = db.prepare('SELECT * FROM maintenance_categories').all();
      const catMap = new Map(categories.map(c => [c.name, c.default_replacement_km || 5000]));

      // Get all vehicles in system (non-deleted)
      const allVehs = db.prepare('SELECT * FROM vehicles WHERE (is_deleted = 0 OR is_deleted IS NULL) ORDER BY plate_number ASC').all();
      const fleetMap = new Map();

      allVehs.forEach(v => {
        fleetMap.set(v.plate_number, {
          vehicle_id: v.vehicle_id,
          plate: v.plate_number,
          department: v.department_id || 'عام',
          is_active: v.is_active === 1,
          is_deleted: v.is_deleted === 1,
          last_km: 0,
          total_tx: 0,
          total_cost: 0,
          total_spent: 0,
          last_service_date: null,
          service_types: {}
        });
      });

      // Aggregate transactions
      transactions.forEach(t => {
        const plates = JSON.parse(t.vehicle_numbers || '[]');
        const price = parseFloat(t.maintenance_price) || 0;
        plates.forEach(plate => {
          if (!fleetMap.has(plate)) {
            fleetMap.set(plate, {
              vehicle_id: 'VEH-' + crypto.randomUUID().slice(0, 6),
              plate,
              department: t.department || 'عام',
              is_active: true,
              is_deleted: false,
              last_km: 0,
              total_tx: 0,
              total_cost: 0,
              total_spent: 0,
              last_service_date: t.submitted_at,
              service_types: {}
            });
          }
          const veh = fleetMap.get(plate);
          veh.total_tx++;
          veh.total_cost += price;
          veh.total_spent += price; // Feature 2: total_spent formula
          if (t.current_km && t.current_km > veh.last_km) {
            veh.last_km = t.current_km;
          }
          if (!veh.last_service_date || new Date(t.submitted_at) > new Date(veh.last_service_date)) {
            veh.last_service_date = t.submitted_at;
          }
          const cat = t.category || 'صيانة عامة';
          if (!veh.service_types[cat]) {
            veh.service_types[cat] = {
              last_date: t.submitted_at,
              last_km: t.current_km || 0,
              default_km: catMap.get(cat) || 5000,
              due_km: (t.current_km || 0) + (catMap.get(cat) || 5000)
            };
          }
        });
      });

      return sendJson(res, 200, { fleet: Array.from(fleetMap.values()) });
    }

    if (pathname === '/api/categories' && req.method === 'GET') {
      const categories = db.prepare('SELECT * FROM maintenance_categories ORDER BY rowid ASC').all();
      return sendJson(res, 200, { categories });
    }

    if ((pathname === '/api/admin/categories' || pathname === '/api/categories') && req.method === 'POST') {
      const body = await parseBody(req);
      const { name, icon, description, default_replacement_km } = body;
      if (!name || !name.trim()) {
        return sendJson(res, 400, { error: 'اسم نوع الصيانة مطلوب' });
      }
      const existing = db.prepare('SELECT category_id FROM maintenance_categories WHERE name = ?').get(name.trim());
      if (existing) {
        return sendJson(res, 400, { error: 'نوع الصيانة موجود مسبقاً' });
      }
      const catId = 'CAT-' + crypto.randomUUID().slice(0, 6);
      const now = new Date().toISOString();
      let defaultKm = parseInt(String(default_replacement_km || '').replace(/[^0-9]/g, ''), 10);
      if (isNaN(defaultKm) || defaultKm <= 0) defaultKm = 5000;

      db.prepare('INSERT INTO maintenance_categories (category_id, name, icon, description, default_replacement_km, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
        catId, name.trim(), icon || '🛞', description || null, defaultKm, now
      );
      const created = db.prepare('SELECT * FROM maintenance_categories WHERE category_id = ?').get(catId);
      return sendJson(res, 201, { success: true, category: created });
    }

    if (((pathname.match(/^\/api\/admin\/categories\/[A-Za-z0-9_-]+$/) && req.method === 'PUT') ||
         (pathname.match(/^\/api\/admin\/categories\/[A-Za-z0-9_-]+\/update$/) && req.method === 'POST'))) {
      const parts = pathname.split('/');
      const catId = parts[4];
      const body = await parseBody(req);
      const cat = db.prepare('SELECT * FROM maintenance_categories WHERE category_id = ?').get(catId);
      if (!cat) return sendJson(res, 404, { error: 'نوع الصيانة غير موجود' });

      let defaultKm = cat.default_replacement_km;
      if (body.default_replacement_km !== undefined) {
        const parsed = parseInt(String(body.default_replacement_km).replace(/[^0-9]/g, ''), 10);
        if (!isNaN(parsed) && parsed > 0) defaultKm = parsed;
      }

      db.prepare(`
        UPDATE maintenance_categories
        SET name = COALESCE(?, name),
            icon = COALESCE(?, icon),
            description = COALESCE(?, description),
            default_replacement_km = ?
        WHERE category_id = ?
      `).run(
        body.name ? body.name.trim() : null,
        body.icon || null,
        body.description !== undefined ? body.description : null,
        defaultKm,
        catId
      );

      const updated = db.prepare('SELECT * FROM maintenance_categories WHERE category_id = ?').get(catId);
      return sendJson(res, 200, { success: true, category: updated });
    }

    if (pathname.match(/^\/api\/admin\/categories\/[A-Za-z0-9_-]+$/) && req.method === 'DELETE') {
      const catId = pathname.split('/').pop();
      db.prepare('DELETE FROM maintenance_categories WHERE category_id = ?').run(catId);
      return sendJson(res, 200, { success: true, message: 'تم حذف نوع الصيانة بنجاح' });
    }

    // --------------------------------------------------------------------------
    // 1.3 System Settings & Branding (المطلب 6)
    // --------------------------------------------------------------------------
    if (pathname === '/api/settings' && req.method === 'GET') {
      const rows = db.prepare('SELECT key, value FROM system_settings').all();
      const settings = {};
      rows.forEach(r => { settings[r.key] = r.value; });
      return sendJson(res, 200, { settings });
    }

    if (pathname === '/api/admin/settings' && req.method === 'POST') {
      const body = await parseBody(req);
      const setStmt = db.prepare(`
        INSERT INTO system_settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
      `);
      for (const [k, v] of Object.entries(body)) {
        if (typeof v === 'string') setStmt.run(k, v);
      }
      const rows = db.prepare('SELECT key, value FROM system_settings').all();
      const updated = {};
      rows.forEach(r => { updated[r.key] = r.value; });
      broadcastEvent('SETTINGS_UPDATED', updated);
      return sendJson(res, 200, { success: true, settings: updated });
    }

    // --------------------------------------------------------------------------
    // 1.4 Login History Log (المطلب 9)
    // --------------------------------------------------------------------------
    if (pathname === '/api/admin/login-history' && req.method === 'GET') {
      const history = db.prepare('SELECT * FROM login_history ORDER BY datetime(timestamp) DESC LIMIT 100').all();
      return sendJson(res, 200, { history });
    }

    // --------------------------------------------------------------------------
    // 1.5 Vehicle Specific Maintenance Dossier (المطلب 8)
    // --------------------------------------------------------------------------
    if (pathname.startsWith('/api/vehicles/') && pathname.endsWith('/history') && req.method === 'GET') {
      const parts = pathname.split('/');
      const encodedPlate = parts[3];
      const plate = decodeURIComponent(encodedPlate);

      const rows = db.prepare(`
        SELECT t.*, u.full_name as user_name, u.department, u.unit
        FROM maintenance_transactions t LEFT JOIN users u ON t.user_id = u.user_id
        WHERE t.vehicle_numbers LIKE ?
        ORDER BY datetime(t.submitted_at) DESC
      `).all(`%${plate}%`);

      const reqRole = (parsedUrl.searchParams.get('role') || viewRole || '').toUpperCase();
      const isAdminReq = reqRole === 'ADMIN';

      const formatted = rows.map(r => {
        const item = {
          ...r,
          vehicle_numbers: JSON.parse(r.vehicle_numbers || '[]'),
          vehicle_images: JSON.parse(r.vehicle_images || '[]'),
          receipt_images: JSON.parse(r.receipt_images || '[]'),
          is_locked: Boolean(r.is_locked)
        };
        if (!isAdminReq) {
          delete item.maintenance_price;
        }
        return item;
      });

      return sendJson(res, 200, { plate, count: formatted.length, transactions: formatted });
    }

    // --------------------------------------------------------------------------
    // 2. Security: Block public self-registration & user profile editing
    // --------------------------------------------------------------------------
    if (pathname === '/api/register' && req.method === 'POST') {
      return sendJson(res, 403, {
        error: 'مرفوض أمنياً: يتم إنشاء وتعيين الحسابات حصرياً من قبل مدير النظام (الأدمن).'
      });
    }

    if (pathname.startsWith('/api/user/') && req.method === 'PUT') {
      return sendJson(res, 403, {
        error: 'مرفوض رقابياً: بيانات الموظف معتمدة ولا يمكن تعديلها إلا من قبل مدير النظام.'
      });
    }

    // --------------------------------------------------------------------------
    // 3. Admin User Management Endpoints
    // --------------------------------------------------------------------------
    if ((pathname === '/api/admin/users' || pathname === '/api/users') && req.method === 'GET') {
      const users = db.prepare(`
        SELECT u.user_id, u.username, u.full_name, u.department as department_id,
               COALESCE(d.name, u.department, 'عام') as department_name,
               u.unit, u.role, u.is_active,
               u.can_add_transaction, u.is_department_manager, u.assigned_department_id,
               u.can_add_dept_members_transactions, u.can_edit_dept_transactions, u.is_read_only,
               u.is_deleted, u.created_at
        FROM users u
        LEFT JOIN departments d ON u.department = d.department_id OR u.department = d.name
        WHERE (u.is_deleted = 0 OR u.is_deleted IS NULL)
        ORDER BY datetime(u.created_at) DESC
      `).all();
      return sendJson(res, 200, { users });
    }

    if ((pathname === '/api/admin/users' || pathname === '/api/users' || pathname === '/api/admin/users/add' || pathname === '/api/admin/users/create') && req.method === 'POST') {
      const body = await parseBody(req);
      const {
        username, password, full_name, department_id, department, unit, role,
        can_add_transaction, is_department_manager, assigned_department_id,
        can_add_dept_members_transactions, can_edit_dept_transactions, is_read_only
      } = body;
      const dept = (department_id || department || '').trim();

      if (!username || !password || !full_name || !dept) {
        return sendJson(res, 400, { error: 'اسم الدخول، كلمة المرور، الاسم الكامل، والقسم حقول مطلوبة' });
      }

      const existing = db.prepare('SELECT user_id FROM users WHERE LOWER(username) = LOWER(?)').get(username.trim());
      if (existing) {
        return sendJson(res, 400, { error: `اسم المستخدم (${username}) مستخدم مسبقاً` });
      }

      const newUserId = 'USR-' + crypto.randomUUID().slice(0, 8);
      const now = new Date().toISOString();
      const fcmToken = 'fcm-' + crypto.randomBytes(8).toString('hex');

      const validRoles = ['ADMIN', 'AUDITOR', 'USER', 'DEPARTMENT_HEAD', 'Department_Head'];
      function normalizeRole(r) {
        if (!r) return null;
        const str = String(r).trim();
        if (str === 'مدير النظام (الأدمن)' || str.toUpperCase() === 'ADMIN') return 'ADMIN';
        if (str === 'مسؤول القسم' || str.toUpperCase() === 'DEPARTMENT_HEAD' || str === 'Department_Head') return 'Department_Head';
        if (str === 'مدقق وصولات' || str.toUpperCase() === 'AUDITOR') return 'AUDITOR';
        if (str === 'مستخدم ميداني' || str.toUpperCase() === 'USER') return 'USER';
        return validRoles.includes(str) ? (str === 'DEPARTMENT_HEAD' ? 'Department_Head' : str) : 'USER';
      }
      let assignedRole = normalizeRole(role) || 'USER';

      // Granular permissions normalization
      let isReadOnly = (is_read_only === 1 || is_read_only === true || is_read_only === '1') ? 1 : 0;
      let canAddTx = isReadOnly ? 0 : ((can_add_transaction === 0 || can_add_transaction === false || can_add_transaction === '0') ? 0 : 1);
      let isDeptMgr = (is_department_manager === 1 || is_department_manager === true || is_department_manager === '1' || assignedRole === 'Department_Head') ? 1 : 0;
      let canAddDeptTx = (isReadOnly || !isDeptMgr) ? 0 : ((can_add_dept_members_transactions === 1 || can_add_dept_members_transactions === true || can_add_dept_members_transactions === '1') ? 1 : 0);
      let canEditDeptTx = (isReadOnly || !isDeptMgr) ? 0 : ((can_edit_dept_transactions === 1 || can_edit_dept_transactions === true || can_edit_dept_transactions === '1') ? 1 : 0);
      let assignedDept = (assigned_department_id || dept || '').trim();

      db.prepare(`
        INSERT INTO users (
          user_id, username, password_hash, full_name, department, unit, fcm_token, role, is_active,
          can_add_transaction, is_department_manager, assigned_department_id,
          can_add_dept_members_transactions, can_edit_dept_transactions, is_read_only, is_deleted, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 0, ?)
      `).run(
        newUserId,
        username.trim(),
        hashPassword(password),
        full_name.trim(),
        dept,
        (unit || '').trim(),
        fcmToken,
        assignedRole,
        canAddTx,
        isDeptMgr,
        assignedDept,
        canAddDeptTx,
        canEditDeptTx,
        isReadOnly,
        now
      );

      logAudit('CREATE_USER', 'users', newUserId, 'admin', 'المدير العام', { username: username.trim(), role: assignedRole, is_read_only: isReadOnly });

      const created = db.prepare(`
        SELECT u.user_id, u.username, u.full_name, u.department as department_id,
               COALESCE(d.name, u.department, 'عام') as department_name,
               u.unit, u.role, u.is_active,
               u.can_add_transaction, u.is_department_manager, u.assigned_department_id,
               u.can_add_dept_members_transactions, u.can_edit_dept_transactions, u.is_read_only,
               u.is_deleted, u.created_at
        FROM users u
        LEFT JOIN departments d ON u.department = d.department_id OR u.department = d.name
        WHERE u.user_id = ?
      `).get(newUserId);
      return sendJson(res, 201, { success: true, message: 'تمت إضافة المستخدم بنجاح', user: created });
    }

    // UPDATE User (supports POST /api/admin/users/update, PUT /api/admin/users/*)
    const isUserUpdate = (pathname === '/api/admin/users/update' && req.method === 'POST') ||
      (pathname.startsWith('/api/admin/users/') && !pathname.endsWith('/toggle-active') && !pathname.endsWith('/delete') && req.method === 'PUT');

    if (isUserUpdate) {
      const body = await parseBody(req);
      let targetUserId = body.user_id || body.id || body.username;
      if (!targetUserId) {
        const rawTail = pathname.replace('/api/admin/users/', '');
        targetUserId = decodeURIComponent(rawTail);
      }
      const {
        full_name, department_id, department, unit, password, is_active, role,
        can_add_transaction, is_department_manager, assigned_department_id,
        can_add_dept_members_transactions, can_edit_dept_transactions, is_read_only
      } = body;
      const dept = (department_id || department);

      const user = db.prepare('SELECT * FROM users WHERE user_id = ? OR username = ?').get(targetUserId, targetUserId);
      if (!user) return sendJson(res, 404, { error: 'المستخدم غير موجود' });

      let newPassHash = user.password_hash;
      if (password && String(password).trim().length > 0) {
        newPassHash = hashPassword(String(password).trim());
      }

      function normalizeRole(r) {
        if (!r) return null;
        const str = String(r).trim();
        if (str === 'مدير النظام (الأدمن)' || str.toUpperCase() === 'ADMIN') return 'ADMIN';
        if (str === 'مسؤول القسم' || str.toUpperCase() === 'DEPARTMENT_HEAD' || str === 'Department_Head') return 'Department_Head';
        if (str === 'مدقق وصولات' || str.toUpperCase() === 'AUDITOR') return 'AUDITOR';
        if (str === 'مستخدم ميداني' || str.toUpperCase() === 'USER') return 'USER';
        return ['ADMIN', 'AUDITOR', 'USER', 'DEPARTMENT_HEAD', 'Department_Head'].includes(str) ? (str === 'DEPARTMENT_HEAD' ? 'Department_Head' : str) : 'USER';
      }
      const assignedRole = role ? normalizeRole(role) : user.role;

      let isReadOnly = is_read_only !== undefined ? ((is_read_only === 1 || is_read_only === true || is_read_only === '1') ? 1 : 0) : (user.is_read_only || 0);
      let isDeptMgr = is_department_manager !== undefined ? ((is_department_manager === 1 || is_department_manager === true || is_department_manager === '1' || assignedRole === 'Department_Head') ? 1 : 0) : (user.is_department_manager || (assignedRole === 'Department_Head' ? 1 : 0));

      let canAddTx;
      let canAddDeptTx;
      let canEditDeptTx;

      if (isReadOnly) {
        canAddTx = 0;
        canAddDeptTx = 0;
        canEditDeptTx = 0;
      } else {
        canAddTx = can_add_transaction !== undefined ? ((can_add_transaction === 1 || can_add_transaction === true || can_add_transaction === '1') ? 1 : 0) : (user.can_add_transaction !== undefined ? user.can_add_transaction : 1);
        canAddDeptTx = (!isDeptMgr) ? 0 : (can_add_dept_members_transactions !== undefined ? ((can_add_dept_members_transactions === 1 || can_add_dept_members_transactions === true || can_add_dept_members_transactions === '1') ? 1 : 0) : (user.can_add_dept_members_transactions || 0));
        canEditDeptTx = (!isDeptMgr) ? 0 : (can_edit_dept_transactions !== undefined ? ((can_edit_dept_transactions === 1 || can_edit_dept_transactions === true || can_edit_dept_transactions === '1') ? 1 : 0) : (user.can_edit_dept_transactions || 0));
      }

      let assignedDept = assigned_department_id !== undefined ? String(assigned_department_id).trim() : (dept ? dept.trim() : (user.assigned_department_id || user.department));

      db.prepare(`
        UPDATE users
        SET full_name = COALESCE(?, full_name),
            department = COALESCE(?, department),
            unit = COALESCE(?, unit),
            password_hash = ?,
            is_active = COALESCE(?, is_active),
            role = COALESCE(?, role),
            can_add_transaction = ?,
            is_department_manager = ?,
            assigned_department_id = ?,
            can_add_dept_members_transactions = ?,
            can_edit_dept_transactions = ?,
            is_read_only = ?
        WHERE user_id = ?
      `).run(
        full_name ? full_name.trim() : null,
        dept ? dept.trim() : null,
        unit !== undefined ? unit.trim() : null,
        newPassHash,
        is_active !== undefined ? (is_active ? 1 : 0) : user.is_active,
        assignedRole,
        canAddTx,
        isDeptMgr,
        assignedDept,
        canAddDeptTx,
        canEditDeptTx,
        isReadOnly,
        user.user_id
      );

      logAudit('UPDATE_USER', 'users', user.user_id, 'admin', 'المدير العام', { username: user.username, role: assignedRole, is_read_only: isReadOnly, can_add_transaction: canAddTx });

      const updated = db.prepare(`
        SELECT u.user_id, u.username, u.full_name, u.department as department_id,
               COALESCE(d.name, u.department, 'عام') as department_name,
               u.unit, u.role, u.is_active,
               u.can_add_transaction, u.is_department_manager, u.assigned_department_id,
               u.can_add_dept_members_transactions, u.can_edit_dept_transactions, u.is_read_only,
               u.is_deleted, u.created_at
        FROM users u
        LEFT JOIN departments d ON u.department = d.department_id OR u.department = d.name
        WHERE u.user_id = ?
      `).get(user.user_id);
      return sendJson(res, 200, { success: true, message: 'تم تحديث بيانات المستخدم وصلاحياته بنجاح', user: updated });
    }

    // TOGGLE USER ACTIVE (supports POST /api/admin/users/toggle-active and POST /api/admin/users/*/toggle-active)
    const isUserToggle = (pathname === '/api/admin/users/toggle-active' && req.method === 'POST') ||
      (pathname.startsWith('/api/admin/users/') && pathname.endsWith('/toggle-active') && req.method === 'POST');

    if (isUserToggle) {
      let body = {};
      try { body = await parseBody(req); } catch(e) {}
      let targetUserId = body.user_id || body.id || body.username;
      if (!targetUserId) {
        const rawTail = pathname.replace('/api/admin/users/', '').replace('/toggle-active', '');
        targetUserId = decodeURIComponent(rawTail);
      }
      const user = db.prepare('SELECT * FROM users WHERE user_id = ? OR username = ?').get(targetUserId, targetUserId);
      if (!user) return sendJson(res, 404, { error: 'المستخدم غير موجود' });
      if (user.username === 'admin') return sendJson(res, 400, { error: 'لا يمكن تجميد الحساب الإداري الرئيسي' });

      const newActive = user.is_active === 1 ? 0 : 1;
      db.prepare('UPDATE users SET is_active = ? WHERE user_id = ?').run(newActive, user.user_id);
      logAudit('TOGGLE_USER_ACTIVE', 'users', user.user_id, 'admin', 'المدير العام', { username: user.username, is_active: newActive });
      return sendJson(res, 200, {
        success: true,
        is_active: newActive,
        message: newActive === 1 ? `تم تفعيل حساب (${user.username}) بنجاح` : `تم تجميد حساب (${user.username}) بنجاح`
      });
    }

    // DELETE USER (supports POST /api/admin/users/delete and DELETE /api/admin/users/*)
    const isUserDelete = (pathname === '/api/admin/users/delete' && req.method === 'POST') ||
      (pathname.startsWith('/api/admin/users') && req.method === 'DELETE');

    if (isUserDelete) {
      let body = {};
      try { body = await parseBody(req); } catch(e) {}
      let targetUserId = body.user_id || body.id || body.username || parsedUrl.searchParams.get('user_id');
      if (!targetUserId) {
        const rawTail = pathname.replace(/^\/api\/admin\/users\/?/, '');
        if (rawTail && rawTail !== 'delete') targetUserId = decodeURIComponent(rawTail);
      }
      const user = db.prepare('SELECT * FROM users WHERE user_id = ? OR username = ?').get(targetUserId, targetUserId);
      if (!user) return sendJson(res, 404, { error: 'المستخدم غير موجود' });

      // Self-delete protection: prevent admin from deleting currently active login account
      const currentUser = body.current_user || parsedUrl.searchParams.get('current_user') || (req.user && req.user.username);
      if (currentUser && (user.user_id === currentUser || user.username === currentUser)) {
        return sendJson(res, 400, { error: 'لا يمكنك حذف حسابك الحالي الذي تستخدمه لتسجيل الدخول إلى المنظومة.' });
      }

      if (user.username === 'admin') return sendJson(res, 400, { error: 'لا يمكن حذف الحساب الإداري الرئيسي (admin)' });

      // Last admin protection: prevent deleting the last active ADMIN in system
      if (user.role === 'ADMIN' || user.role === 'admin') {
        const adminCount = db.prepare("SELECT COUNT(*) as cnt FROM users WHERE (role = 'ADMIN' OR role = 'admin') AND is_active = 1 AND user_id != ? AND (is_deleted = 0 OR is_deleted IS NULL)").get(user.user_id);
        if (adminCount && adminCount.cnt === 0) {
          return sendJson(res, 400, { error: 'لا يمكن حذف هذا الحساب، لأنه آخر حساب مدير نظام (Admin) نشط في المنظومة.' });
        }
      }

      const now = new Date().toISOString();
      // Save complete snapshot to deleted_records table (سلة المحذوفات)
      try {
        db.prepare(`
          INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by, deleted_at)
          VALUES ('user', ?, ?, 'admin', ?)
        `).run(user.user_id, JSON.stringify(user), now);
      } catch(snapErr) {
        console.warn('User delete snapshot notice:', snapErr);
      }

      // Soft delete: Mark is_deleted = 1
      db.prepare('UPDATE users SET is_deleted = 1, deleted_at = ?, deleted_by = ? WHERE user_id = ?').run(now, 'admin', user.user_id);
      logAudit('SOFT_DELETE_USER', 'users', user.user_id, 'admin', 'المدير العام', { username: user.username });
      broadcastEvent('USER_DELETED', { user_id: user.user_id, username: user.username });
      return sendJson(res, 200, { success: true, message: `تم حذف حساب المستخدم (${user.username}) بنجاح ونقله لسلة المحذوفات ✅` });
    }

    // --------------------------------------------------------------------------
    // 4. Admin Broadcast Notifications (المطلب 8)
    // --------------------------------------------------------------------------
    if ((pathname === '/api/admin/broadcast' || pathname === '/api/broadcast') && req.method === 'POST') {
      const body = await parseBody(req);
      const { title, purpose, message, sender_id, target_type, target_user_ids } = body;

      if (!title || !message) {
        return sendJson(res, 400, { error: 'عنوان الإشعار ونص الرسالة مطلوبان' });
      }

      let sender = null;
      if (sender_id) {
        sender = db.prepare('SELECT user_id, username, full_name, role, department FROM users WHERE user_id = ? OR LOWER(username) = LOWER(?)').get(sender_id, sender_id);
      }

      const isDeptHead = sender && (sender.role === 'DEPARTMENT_HEAD' || sender.role === 'Department_Head');
      const now = new Date().toISOString();

      let targetUsers = [];

      if (isDeptHead) {
        // Task 7: Department Head MUST only target their department users!
        if (target_type === 'ALL') {
          return sendJson(res, 403, { error: 'غير مصرح: لا يمكنك بث إشعار لجميع مستخدمي النظام' });
        }

        const deptUsers = db.prepare(`
          SELECT user_id, department FROM users
          WHERE is_active = 1 AND (department = ? OR department IN (SELECT name FROM departments WHERE department_id = ?) OR department IN (SELECT department_id FROM departments WHERE name = ?))
        `).all(sender.department, sender.department, sender.department);

        const deptUserIds = new Set(deptUsers.map(u => u.user_id));

        if (Array.isArray(target_user_ids) && target_user_ids.length > 0) {
          // Verify EVERY target belongs to sender's department
          for (const uid of target_user_ids) {
            if (!deptUserIds.has(uid)) {
              return sendJson(res, 403, { error: 'لا يمكنك إرسال إشعار لمستخدمين خارج قسمك' });
            }
          }
          targetUsers = target_user_ids.map(id => ({ user_id: id }));
        } else {
          // All users in this department
          targetUsers = deptUsers;
        }
      } else {
        // Admin or default broadcast
        if (Array.isArray(target_user_ids) && target_user_ids.length > 0) {
          targetUsers = target_user_ids.map(id => ({ user_id: id }));
        } else {
          targetUsers = db.prepare('SELECT user_id FROM users WHERE is_active = 1').all();
        }
      }

      const insertStmt = db.prepare(`
        INSERT INTO notifications (notification_id, user_id, transaction_id, title, purpose, message, type, is_read, created_at)
        VALUES (?, ?, NULL, ?, ?, ?, 'ADMIN_BROADCAST', 0, ?)
      `);

      for (const u of targetUsers) {
        const notifId = 'BROADCAST-' + crypto.randomUUID().slice(0, 8);
        insertStmt.run(notifId, u.user_id, title, purpose || (isDeptHead ? 'توجيه من مسؤول القسم' : 'توجيه إداري عام'), message, now);
      }

      // Live SSE Broadcast
      broadcastEvent('ADMIN_BROADCAST', {
        title,
        purpose: purpose || (isDeptHead ? 'توجيه من مسؤول القسم' : 'توجيه إداري عام'),
        message,
        department: isDeptHead ? sender.department : null,
        timestamp: now
      });

      return sendJson(res, 200, {
        success: true,
        message: `تم إرسال الإشعار بنجاح إلى المستهدفين (${targetUsers.length} مستخدم)`
      });
    }

    // --------------------------------------------------------------------------
    // 5. Vehicle Suggestions (Dropdown list - المطلب 7)
    // --------------------------------------------------------------------------
    if (pathname === '/api/vehicles/history' && req.method === 'GET') {
      const rows = db.prepare('SELECT vehicle_numbers FROM maintenance_transactions').all();
      const vehicleSet = new Set();
      for (const row of rows) {
        try {
          const arr = JSON.parse(row.vehicle_numbers);
          if (Array.isArray(arr)) {
            arr.forEach(num => num && vehicleSet.add(num.trim()));
          }
        } catch (e) {}
      }
      return sendJson(res, 200, { suggestions: Array.from(vehicleSet) });
    }

    // --------------------------------------------------------------------------
    // 6. Transactions List & Filter
    // --------------------------------------------------------------------------
    if (pathname === '/api/transactions' && req.method === 'GET') {
      const userId = parsedUrl.searchParams.get('user_id');
      const status = parsedUrl.searchParams.get('status');
      const search = parsedUrl.searchParams.get('search');
      const category = parsedUrl.searchParams.get('category');
      const department = parsedUrl.searchParams.get('department');
      const viewRole = parsedUrl.searchParams.get('view_role'); // 'AUDITOR' or 'ADMIN'

      let query = `
        SELECT t.*, u.full_name as user_name, u.department, u.unit, u.fcm_token, u.username
        FROM maintenance_transactions t LEFT JOIN users u ON t.user_id = u.user_id
        WHERE 1=1
      `;
      const params = [];

      if (userId) {
        query += ' AND t.user_id = ?';
        params.push(userId);
      }

      // Role-based visibility enforcement (المطلب 1 & Task 7):
      // Admin ONLY sees transactions forwarded by auditor ('PENDING_ADMIN') or 'AUDITED'!
      // Department Head sees ALL stages (do NOT filter out verified or pending items) for their department!
      const vRoleUpper = (viewRole || parsedUrl.searchParams.get('role') || req.headers['x-user-role'] || '').toString().trim().toUpperCase();
      if (vRoleUpper === 'DEPARTMENT_HEAD' || vRoleUpper === 'DEPT_HEAD') {
        // Department Head sees all stages
        if (status && status !== 'ALL' && status !== 'FEED') {
          query += ' AND t.status = ?';
          params.push(status);
        }
      } else if (viewRole === 'ADMIN' && (!status || status === 'FEED')) {
        query += " AND t.status = 'PENDING_ADMIN'";
      } else if (viewRole === 'AUDITOR' && (!status || status === 'FEED')) {
        query += " AND t.status = 'PENDING_AUDITOR'";
      } else if (status === 'IN_PROGRESS' || status === 'PENDING_PROCEDURES') {
        query += " AND (t.status = 'PENDING_ADMIN' OR t.status = 'PENDING_AUDITOR' OR t.status = 'IN_PROGRESS')";
      } else if (status && status !== 'ALL') {
        query += ' AND t.status = ?';
        params.push(status);
      }

      if (category && category !== 'ALL') {
        query += ' AND t.category = ?';
        params.push(category);
      }
      if (department && department !== 'ALL') {
        query += ' AND (u.department = ? OR u.department IN (SELECT name FROM departments WHERE department_id = ?) OR u.department IN (SELECT department_id FROM departments WHERE name = ?))';
        params.push(department, department, department);
      }
      if (search) {
        query += ' AND (t.vehicle_numbers LIKE ? OR u.full_name LIKE ? OR t.transaction_id LIKE ?)';
        const s = `%${search}%`;
        params.push(s, s, s);
      }

      query += ' ORDER BY datetime(t.submitted_at) DESC';

      const rows = db.prepare(query).all(...params);
      const reqRole = (parsedUrl.searchParams.get('role') || viewRole || '').toUpperCase();
      const isAdminReq = reqRole === 'ADMIN';

      const formatted = rows.map(r => {
        const item = {
          ...r,
          vehicle_numbers: JSON.parse(r.vehicle_numbers || '[]'),
          vehicle_images: JSON.parse(r.vehicle_images || '[]'),
          receipt_images: JSON.parse(r.receipt_images || '[]'),
          is_locked: Boolean(r.is_locked)
        };
        if (!isAdminReq) {
          delete item.maintenance_price;
        }
        return item;
      });

      return sendJson(res, 200, { transactions: formatted });
    }

    // --------------------------------------------------------------------------
    // 7. Submit New Transaction (Goes to Auditor first - المطلب 1)
    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------
    // Vehicles Management Endpoints (Feature 3 - Upgraded for v5)
    // --------------------------------------------------------------------------
    if (pathname === '/api/vehicles' && req.method === 'GET') {
      const role = (parsedUrl.searchParams.get('role') || '').toUpperCase();
      const userId = parsedUrl.searchParams.get('user_id');
      const deptParam = parsedUrl.searchParams.get('department_id') || parsedUrl.searchParams.get('department');
      const isAdmin = role === 'ADMIN';

      let rows;
      if (isAdmin) {
        if (deptParam && deptParam !== 'ALL') {
          rows = db.prepare(`
            SELECT v.*, COALESCE(d.name, v.department_id, 'عام') as department_name
            FROM vehicles v
            LEFT JOIN departments d ON v.department_id = d.department_id OR v.department_id = d.name
            WHERE (v.is_deleted = 0 OR v.is_deleted IS NULL)
              AND (v.department_id = ? OR v.department_id IN (SELECT department_id FROM departments WHERE name = ?) OR v.department_id IN (SELECT name FROM departments WHERE department_id = ?))
            ORDER BY v.plate_number ASC
          `).all(deptParam, deptParam, deptParam);
        } else {
          rows = db.prepare(`
            SELECT v.*, COALESCE(d.name, v.department_id, 'عام') as department_name
            FROM vehicles v
            LEFT JOIN departments d ON v.department_id = d.department_id OR v.department_id = d.name
            WHERE (v.is_deleted = 0 OR v.is_deleted IS NULL)
            ORDER BY v.plate_number ASC
          `).all();
        }
      } else {
        // Field User or Department Head: STRICT isolation to their own department!
        let targetDept = deptParam;
        if (!targetDept && userId) {
          const u = db.prepare('SELECT department FROM users WHERE user_id = ? OR username = ?').get(userId, userId);
          if (u) targetDept = u.department;
        }
        if (targetDept) {
          rows = db.prepare(`
            SELECT v.*, COALESCE(d.name, v.department_id, 'عام') as department_name
            FROM vehicles v
            LEFT JOIN departments d ON v.department_id = d.department_id OR v.department_id = d.name
            WHERE v.is_active = 1 AND (v.is_deleted = 0 OR v.is_deleted IS NULL)
              AND (v.department_id = ? OR v.department_id IN (SELECT department_id FROM departments WHERE name = ?) OR v.department_id IN (SELECT name FROM departments WHERE department_id = ?))
            ORDER BY v.plate_number ASC
          `).all(targetDept, targetDept, targetDept);
        } else {
          rows = db.prepare(`
            SELECT v.*, COALESCE(d.name, v.department_id, 'عام') as department_name
            FROM vehicles v
            LEFT JOIN departments d ON v.department_id = d.department_id OR v.department_id = d.name
            WHERE v.is_active = 1 AND (v.is_deleted = 0 OR v.is_deleted IS NULL)
            ORDER BY v.plate_number ASC
          `).all();
        }
      }
      return sendJson(res, 200, { vehicles: rows });
    }

    // POST /api/admin/vehicles - Create Vehicle
    if ((pathname === '/api/admin/vehicles' || pathname === '/api/vehicles' || pathname === '/api/admin/vehicles/add') && req.method === 'POST') {
      const body = await parseBody(req);
      const { plate_number, department_id } = body;
      if (!plate_number || !plate_number.trim()) {
        return sendJson(res, 400, { error: 'رقم العجلة مطلوب' });
      }
      const trimmedPlate = plate_number.trim();
      const existing = db.prepare('SELECT vehicle_id FROM vehicles WHERE plate_number = ? AND (is_deleted = 0 OR is_deleted IS NULL)').get(trimmedPlate);
      if (existing) {
        return sendJson(res, 400, { error: 'رقم العجلة موجود مسبقاً' });
      }
      const vehId = 'VEH-' + crypto.randomUUID().slice(0, 6);
      const now = new Date().toISOString();
      db.prepare('INSERT INTO vehicles (vehicle_id, plate_number, department_id, is_active, is_deleted, created_at) VALUES (?, ?, ?, 1, 0, ?)').run(
        vehId, trimmedPlate, department_id || null, now
      );
      const created = db.prepare(`
        SELECT v.*, COALESCE(d.name, v.department_id, 'عام') as department_name
        FROM vehicles v
        LEFT JOIN departments d ON v.department_id = d.department_id OR v.department_id = d.name
        WHERE v.vehicle_id = ?
      `).get(vehId);
      broadcastEvent('VEHICLE_CREATED', created);
      return sendJson(res, 201, { success: true, vehicle: created });
    }

    // UPDATE Vehicle (supports POST /api/vehicles/update, POST /api/admin/vehicles/update, PUT /api/admin/vehicles/*, PATCH /api/admin/vehicles/*)
    const isVehUpdate = (pathname === '/api/admin/vehicles/update' && req.method === 'POST') ||
      (pathname === '/api/vehicles/update' && req.method === 'POST') ||
      ((pathname.startsWith('/api/admin/vehicles/') || pathname.startsWith('/api/vehicles/')) && !pathname.endsWith('/toggle-active') && !pathname.endsWith('/toggle-status') && !pathname.endsWith('/delete') && (req.method === 'PUT' || req.method === 'PATCH'));

    if (isVehUpdate) {
      const body = await parseBody(req);
      let targetId = body.vehicle_id || body.id || body.old_vehicle_number || body.plate_number || body.vehicle_number;
      if (!targetId) {
        const rawTail = pathname.replace(/^\/api\/(admin\/)?vehicles\//, '');
        targetId = decodeURIComponent(rawTail);
      }
      const plateInput = body.plate_number || body.vehicle_number;
      const { department_id, is_active } = body;

      let veh = db.prepare('SELECT * FROM vehicles WHERE vehicle_id = ? OR plate_number = ?').get(targetId, targetId);
      if (!veh && targetId) {
        // Auto-create entry if vehicle was aggregated from transactions
        const newVehId = 'VEH-' + crypto.randomUUID().slice(0, 6);
        db.prepare(`
          INSERT INTO vehicles (vehicle_id, plate_number, department_id, is_active, is_deleted, created_at)
          VALUES (?, ?, ?, 1, 0, ?)
        `).run(newVehId, targetId, department_id || 'DEPT-001', new Date().toISOString());
        veh = db.prepare('SELECT * FROM vehicles WHERE vehicle_id = ?').get(newVehId);
      }
      if (!veh) return sendJson(res, 404, { error: 'العجلة غير موجودة' });
      const plate_number = plateInput || veh.plate_number;

      if (!plate_number || !plate_number.trim()) {
        return sendJson(res, 400, { error: 'رقم العجلة مطلوب' });
      }
      const newPlate = plate_number.trim();

      const existing = db.prepare('SELECT vehicle_id FROM vehicles WHERE plate_number = ? AND vehicle_id != ? AND (is_deleted = 0 OR is_deleted IS NULL)').get(newPlate, veh.vehicle_id);
      if (existing) {
        return sendJson(res, 400, { error: 'رقم العجلة مستخدم مسبقاً لعجلة أخرى' });
      }

      const oldPlate = veh.plate_number;
      const deptId = department_id !== undefined ? department_id : veh.department_id;
      const activeStatus = is_active !== undefined ? (is_active ? 1 : 0) : veh.is_active;

      db.prepare('UPDATE vehicles SET plate_number = ?, department_id = ?, is_active = ? WHERE vehicle_id = ?').run(
        newPlate, deptId, activeStatus, veh.vehicle_id
      );

      // If plate number changed, cascade update in transactions and maintenance_requests
      if (oldPlate !== newPlate) {
        const txs = db.prepare('SELECT transaction_id, vehicle_numbers FROM maintenance_transactions WHERE vehicle_numbers LIKE ?').all(`%${oldPlate}%`);
        for (const t of txs) {
          try {
            const arr = Array.isArray(t.vehicle_numbers) ? t.vehicle_numbers : JSON.parse(t.vehicle_numbers);
            const updatedArr = arr.map(p => p === oldPlate ? newPlate : p);
            db.prepare('UPDATE maintenance_transactions SET vehicle_numbers = ? WHERE transaction_id = ?').run(JSON.stringify(updatedArr), t.transaction_id);
          } catch(e) {}
        }
        db.prepare('UPDATE maintenance_requests SET vehicle_number = ? WHERE vehicle_number = ?').run(newPlate, oldPlate);
      }

      const updated = db.prepare(`
        SELECT v.*, COALESCE(d.name, v.department_id, 'عام') as department_name
        FROM vehicles v
        LEFT JOIN departments d ON v.department_id = d.department_id OR v.department_id = d.name
        WHERE v.vehicle_id = ?
      `).get(veh.vehicle_id);
      broadcastEvent('VEHICLE_UPDATED', updated);
      return sendJson(res, 200, { success: true, message: 'تم تعديل بيانات العجلة بنجاح', vehicle: updated });
    }

    // TOGGLE ACTIVE (supports POST /api/admin/vehicles/toggle-active, POST /api/vehicles/toggle-status)
    const isVehToggle = (pathname === '/api/admin/vehicles/toggle-active' && req.method === 'POST') ||
      (pathname === '/api/vehicles/toggle-status' && req.method === 'POST') ||
      (pathname.startsWith('/api/admin/vehicles/') && pathname.endsWith('/toggle-active') && req.method === 'POST');

    if (isVehToggle) {
      let body = {};
      try { body = await parseBody(req); } catch(e) {}
      let targetId = body.vehicle_id || body.id || body.plate_number || body.plate;
      if (!targetId) {
        const rawTail = pathname.replace('/api/admin/vehicles/', '').replace('/toggle-active', '');
        targetId = decodeURIComponent(rawTail);
      }

      let veh = db.prepare('SELECT * FROM vehicles WHERE vehicle_id = ? OR plate_number = ?').get(targetId, targetId);
      if (!veh) {
        const newVehId = 'VEH-' + crypto.randomUUID().slice(0, 6);
        db.prepare('INSERT OR IGNORE INTO vehicles (vehicle_id, plate_number, department_id, is_active, is_deleted, created_at) VALUES (?, ?, ?, 1, 0, ?)').run(
          newVehId, targetId, 'DEPT-001', new Date().toISOString()
        );
        veh = db.prepare('SELECT * FROM vehicles WHERE vehicle_id = ? OR plate_number = ?').get(newVehId, targetId);
      }
      if (!veh) return sendJson(res, 404, { error: 'العجلة غير موجودة' });

      let newActive;
      if (body.is_active !== undefined) {
        newActive = (body.is_active === 1 || body.is_active === '1' || body.is_active === true) ? 1 : 0;
      } else {
        newActive = veh.is_active === 1 ? 0 : 1;
      }
      db.prepare('UPDATE vehicles SET is_active = ? WHERE vehicle_id = ?').run(newActive, veh.vehicle_id);
      const updated = db.prepare(`
        SELECT v.*, COALESCE(d.name, v.department_id, 'عام') as department_name
        FROM vehicles v
        LEFT JOIN departments d ON v.department_id = d.department_id OR v.department_id = d.name
        WHERE v.vehicle_id = ?
      `).get(veh.vehicle_id);
      broadcastEvent('VEHICLE_STATUS_UPDATED', updated);
      return sendJson(res, 200, {
        success: true,
        message: newActive === 1 ? 'تم تفعيل العجلة بنجاح' : 'تم تعطيل العجلة بنجاح',
        vehicle: updated
      });
    }

    // DELETE VEHICLE (supports POST /api/admin/vehicles/delete, POST /api/vehicles/delete, DELETE /api/admin/vehicles, DELETE /api/vehicles)
    const isVehDelete = (pathname === '/api/admin/vehicles/delete' && req.method === 'POST') ||
      (pathname === '/api/vehicles/delete' && req.method === 'POST') ||
      ((pathname.startsWith('/api/admin/vehicles') || pathname.startsWith('/api/vehicles')) && req.method === 'DELETE');

    if (isVehDelete) {
      let body = {};
      try { body = await parseBody(req); } catch(e) {}
      let targetId = body.vehicle_id || body.id || body.plate_number || body.plate ||
                     parsedUrl.searchParams.get('id') || parsedUrl.searchParams.get('plate') || parsedUrl.searchParams.get('vehicle_id');

      if (!targetId) {
        const rawTail = pathname.replace(/^\/api\/(admin\/)?vehicles\/?/, '');
        if (rawTail && rawTail !== 'delete') {
          targetId = decodeURIComponent(rawTail);
        }
      }

      if (!targetId) {
        return sendJson(res, 400, { error: 'معرف أو رقم العجلة مطلوب للحذف' });
      }

      let veh = db.prepare('SELECT * FROM vehicles WHERE vehicle_id = ? OR plate_number = ?').get(targetId, targetId);
      const now = new Date().toISOString();
      const adminUser = body.admin || parsedUrl.searchParams.get('admin') || 'المدير العام (الأدمن)';

      if (!veh) {
        // Auto-create soft-deleted entry if vehicle was derived from transactions
        const newVehId = 'VEH-' + crypto.randomUUID().slice(0, 6);
        db.prepare(`
          INSERT INTO vehicles (vehicle_id, plate_number, department_id, is_active, is_deleted, deleted_at, deleted_by, created_at)
          VALUES (?, ?, 'DEPT-001', 0, 1, ?, ?, ?)
        `).run(newVehId, targetId, now, adminUser, now);
        veh = db.prepare('SELECT * FROM vehicles WHERE vehicle_id = ?').get(newVehId);
      } else {
        // Soft delete vehicle
        db.prepare('UPDATE vehicles SET is_deleted = 1, is_active = 0, deleted_at = ?, deleted_by = ? WHERE vehicle_id = ?').run(
          now, adminUser, veh.vehicle_id
        );
      }

      // Log to deleted_records
      db.prepare(`
        INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by, deleted_at)
        VALUES ('vehicle', ?, ?, ?, ?)
      `).run(veh.vehicle_id, JSON.stringify(veh), adminUser, now);

      broadcastEvent('VEHICLE_DELETED', { vehicle_id: veh.vehicle_id, plate_number: veh.plate_number });
      return sendJson(res, 200, {
        success: true,
        message: `تم حذف العجلة (${veh.plate_number}) ونقلها إلى سلة المحذوفات بنجاح`
      });
    }

    // --------------------------------------------------------------------------
    // Recycle Bin Endpoints (Feature 1: جدول المحذوفات)
    // --------------------------------------------------------------------------
    if ((pathname === '/api/deleted-records' || pathname === '/api/admin/recycle-bin' || pathname === '/api/admin/deleted-records') && req.method === 'GET') {
      const rows = db.prepare('SELECT * FROM deleted_records ORDER BY datetime(deleted_at) DESC').all();
      return sendJson(res, 200, { success: true, count: rows.length, data: rows, deleted_records: rows });
    }

    if ((pathname === '/api/admin/recycle-bin/restore' || pathname === '/api/deleted-records/restore' || pathname.match(/^\/api\/deleted-records\/[0-9]+\/restore$/)) && req.method === 'POST') {
      const body = await parseBody(req);
      const parts = pathname.split('/');
      const urlId = (parts.length >= 4 && parts[3] === 'restore') ? parts[2] : null;
      const id = body.id || body.trashId || urlId;
      const record = db.prepare('SELECT * FROM deleted_records WHERE id = ?').get(id);
      if (!record) return sendJson(res, 404, { error: 'سجل المحذوفات غير موجود' });

      if (record.entity_type === 'transaction') {
        db.prepare('UPDATE maintenance_transactions SET is_deleted = 0, deleted_at = NULL, deleted_by = NULL WHERE transaction_id = ?').run(record.entity_id);
      } else if (record.entity_type === 'vehicle') {
        db.prepare('UPDATE vehicles SET is_deleted = 0, deleted_at = NULL, deleted_by = NULL WHERE vehicle_id = ?').run(record.entity_id);
      } else if (record.entity_type === 'user' || record.entity_type === 'users') {
        db.prepare('UPDATE users SET is_deleted = 0, deleted_at = NULL, deleted_by = NULL WHERE user_id = ?').run(record.entity_id);
        try {
          const u = JSON.parse(record.record_snapshot);
          const cols = Object.keys(u);
          const placeholders = cols.map(() => '?').join(', ');
          db.prepare(`INSERT OR REPLACE INTO users (${cols.join(', ')}) VALUES (${placeholders})`).run(...cols.map(c => u[c]));
          db.prepare('UPDATE users SET is_deleted = 0, deleted_at = NULL, deleted_by = NULL WHERE user_id = ?').run(record.entity_id);
        } catch(e) {
          console.warn('Restore user err:', e);
        }
      } else if (record.entity_type === 'department' || record.entity_type === 'departments') {
        db.prepare('UPDATE departments SET is_deleted = 0, deleted_at = NULL, deleted_by = NULL WHERE department_id = ?').run(record.entity_id);
        try {
          const d = JSON.parse(record.record_snapshot);
          db.prepare('INSERT OR REPLACE INTO departments (department_id, name, created_at, is_deleted) VALUES (?, ?, ?, 0)').run(
            d.department_id || d.id || record.entity_id,
            d.name,
            d.created_at || new Date().toISOString()
          );
        } catch(e) {
          console.warn('Restore dept err:', e);
        }
      }
      db.prepare('DELETE FROM deleted_records WHERE id = ?').run(id);

      logAudit('RESTORE_RECORD', record.entity_type, record.entity_id, 'admin', 'المدير العام', { record_id: id });
      broadcastEvent('RECORD_RESTORED', { entity_type: record.entity_type, entity_id: record.entity_id });
      return sendJson(res, 200, { success: true, message: 'تم استرجاع السجل بنجاح من سلة المحذوفات' });
    }

    const isPermanentDelete = (pathname.match(/^\/api\/admin\/recycle-bin\/permanent\/[0-9]+$/) && (req.method === 'DELETE' || req.method === 'POST')) ||
      (pathname === '/api/admin/recycle-bin/permanent' && req.method === 'POST');

    if (isPermanentDelete) {
      let body = {};
      try { body = await parseBody(req); } catch(e) {}
      let id = body.id;
      if (!id) {
        const parts = pathname.split('/');
        id = parseInt(parts[parts.length - 1], 10);
      }
      if (isNaN(id)) {
        return sendJson(res, 400, { error: 'معرف السجل غير صالح' });
      }

      // Admin password confirmation enforcement
      const providedPass = body.password || body.admin_password || parsedUrl.searchParams.get('password') || req.headers['x-admin-password'];
      if (!providedPass || String(providedPass).trim().length === 0) {
        return sendJson(res, 401, { error: 'يرجى إدخال كلمة مرور مدير النظام (الأدمن) لتأكيد الحذف النهائي غير القابل للتراجع' });
      }

      const adminAcc = db.prepare("SELECT * FROM users WHERE (role = 'ADMIN' OR role = 'admin' OR username = 'admin') AND is_active = 1 LIMIT 1").get();
      if (!adminAcc || !verifyPassword(String(providedPass).trim(), adminAcc.password_hash)) {
        return sendJson(res, 401, { error: 'كلمة مرور مدير النظام (الأدمن) غير صحيحة، تم إلغاء عملية الحذف النهائي ❌' });
      }

      const record = db.prepare('SELECT * FROM deleted_records WHERE id = ?').get(id);
      if (!record) return sendJson(res, 404, { error: 'السجل غير موجود أو تم حذفه مسبقاً' });

      if (record.entity_type === 'transaction') {
        db.prepare('DELETE FROM maintenance_transactions WHERE transaction_id = ?').run(record.entity_id);
      } else if (record.entity_type === 'vehicle') {
        db.prepare('DELETE FROM vehicles WHERE vehicle_id = ?').run(record.entity_id);
      } else if (record.entity_type === 'user' || record.entity_type === 'users') {
        db.prepare('DELETE FROM users WHERE user_id = ?').run(record.entity_id);
      } else if (record.entity_type === 'department' || record.entity_type === 'departments') {
        db.prepare('DELETE FROM departments WHERE department_id = ?').run(record.entity_id);
      }
      db.prepare('DELETE FROM deleted_records WHERE id = ?').run(id);

      logAudit('PERMANENT_DELETE', record.entity_type, record.entity_id, adminAcc.user_id, adminAcc.full_name, { record_id: id });
      return sendJson(res, 200, { success: true, message: 'تم حذف السجل نهائياً من قاعدة البيانات بنجاح ✅' });
    }

    // --------------------------------------------------------------------------
    // Delete Transaction Endpoint (Feature 1: Admin Delete)
    // --------------------------------------------------------------------------
    if ((pathname.match(/^\/api\/admin\/transactions\/[A-Za-z0-9_-]+$/) || pathname.match(/^\/api\/transactions\/[A-Za-z0-9_-]+$/)) && req.method === 'DELETE') {
      const userRole = (req.headers['x-user-role'] || parsedUrl.searchParams.get('role') || '').toUpperCase();
      if (userRole && userRole !== 'ADMIN') {
        return sendJson(res, 403, { error: 'عذراً، صلاحية حذف المعاملات مخصصة للأدمن فقط' });
      }
      const parts = pathname.split('/');
      const txId = parts[parts.length - 1];
      const tx = db.prepare('SELECT * FROM maintenance_transactions WHERE transaction_id = ?').get(txId);
      if (!tx) return sendJson(res, 404, { error: 'المعاملة غير موجودة' });
      const now = new Date().toISOString();
      const adminUser = parsedUrl.searchParams.get('admin') || 'المدير العام (الأدمن)';

      // Soft delete transaction
      db.prepare('UPDATE maintenance_transactions SET is_deleted = 1, deleted_at = ?, deleted_by = ? WHERE transaction_id = ?').run(now, adminUser, txId);

      // Log to deleted_records
      db.prepare(`
        INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by, deleted_at)
        VALUES ('transaction', ?, ?, ?, ?)
      `).run(txId, JSON.stringify(tx), adminUser, now);

      broadcastEvent('TRANSACTION_DELETED', { transaction_id: txId });
      return sendJson(res, 200, { success: true, message: 'تم حذف المعاملة ونقلها إلى سلة المحذوفات بنجاح' });
    }

    // --------------------------------------------------------------------------
    // Excel Export Backend Endpoint (Bug 2 & 3: Binary .xlsx with Arabic RTL)
    // --------------------------------------------------------------------------
    if (pathname === '/api/export/transactions.xlsx' && req.method === 'GET') {
      const role = (parsedUrl.searchParams.get('role') || '').toUpperCase();
      const isAdmin = role === 'ADMIN';

      const rows = db.prepare(`
        SELECT t.*, u.full_name as user_name, u.department, u.unit
        FROM maintenance_transactions t
        LEFT JOIN users u ON t.user_id = u.user_id
        WHERE (t.is_deleted = 0 OR t.is_deleted IS NULL)
        ORDER BY datetime(t.submitted_at) DESC
      `).all();

      const excelData = rows.map(r => {
        const plates = JSON.parse(r.vehicle_numbers || '[]').join('، ');
        const item = {
          'رقم المعاملة': r.transaction_id,
          'أرقام العجلات': plates,
          'نوع الصيانة': r.category || 'صيانة عامة',
          'قراءة العداد عند الصيانة (كم)': r.current_km || 0,
          'تاريخ الإرسال': r.submitted_at ? new Date(r.submitted_at).toLocaleString('ar-IQ') : '',
          'الموظف / المسؤول الميداني': r.user_name || '',
          'القسم': r.department || '',
          'حالة المعاملة': r.status === 'AUDITED' ? 'معتمدة ومصروفة' : (r.status === 'PENDING_ADMIN' ? 'بانتظار موافقة الإدارة' : (r.status === 'IN_PROGRESS' ? 'قيد المراجعة والتعديل' : 'بانتظار تدقيق الوصولات'))
        };

        if (isAdmin) {
          item['سعر الصيانة (د.ع)'] = parseFloat(r.maintenance_price) || 0;
        }

        item['ملاحظات'] = r.notes || '';
        item['ملاحظة مدقق الوصولات'] = r.auditor_note || '';
        item['ملاحظة الإدارة'] = r.admin_note || '';
        return item;
      });

      const wb = XLSX.utils.book_new();
      const ws = XLSX.utils.json_to_sheet(excelData);

      // Set RTL direction for proper Arabic display
      ws['!views'] = [{ rightToLeft: true }];

      // Column widths
      const colWidths = [
        { wch: 18 }, { wch: 24 }, { wch: 20 }, { wch: 16 }, { wch: 22 }, { wch: 22 }, { wch: 18 }, { wch: 20 }
      ];
      if (isAdmin) colWidths.push({ wch: 16 });
      colWidths.push({ wch: 25 }, { wch: 25 }, { wch: 25 });
      ws['!cols'] = colWidths;

      XLSX.utils.book_append_sheet(wb, ws, 'سجل الصيانة');
      const excelBuffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

      res.writeHead(200, {
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': 'attachment; filename="maintenance_report.xlsx"',
        'Content-Length': excelBuffer.length
      });
      return res.end(excelBuffer);
    }

    if (pathname === '/api/transactions' && req.method === 'POST') {
      const body = await parseBody(req);
      const { user_id, vehicle_numbers, vehicle_images, receipt_images, category } = body;

      if (!user_id) return sendJson(res, 400, { error: 'معرف المستخدم مفقود' });

      // Look up user by user_id OR username
      const user = db.prepare('SELECT user_id, username, full_name, department, unit, role, is_active, can_add_transaction, is_department_manager, assigned_department_id, can_add_dept_members_transactions, can_edit_dept_transactions, is_read_only FROM users WHERE user_id = ? OR LOWER(username) = LOWER(?)').get(user_id, user_id);
      if (!user || user.is_active !== 1) {
        return sendJson(res, 403, { error: 'المستخدم غير موجود أو موقوف' });
      }

      // Check Read-Only Restriction
      if (user.is_read_only === 1) {
        return sendJson(res, 403, { error: 'حسابك مخصص للقراءة والاطلاع فقط، لا تملك صلاحية إضافة معاملات.' });
      }

      // Member user delegation check (مسؤول القسم يضيف لمعاملة لمنتسب)
      let transactionOwnerId = user.user_id;
      let memberUserId = null;
      let transactionDept = user.assigned_department_id || user.department;

      if (body.member_user_id) {
        const isMgr = (user.is_department_manager === 1 || user.role === 'DEPARTMENT_HEAD' || user.role === 'ADMIN');
        const canAddMembers = (user.can_add_dept_members_transactions === 1 || user.role === 'ADMIN');
        if (!isMgr || !canAddMembers) {
          return sendJson(res, 403, { error: 'ليس لديك صلاحية إضافة معاملات لمنتسبي القسم.' });
        }
        const member = db.prepare('SELECT user_id, username, full_name, department, is_active FROM users WHERE user_id = ? OR username = ?').get(body.member_user_id, body.member_user_id);
        if (!member) {
          return sendJson(res, 404, { error: 'الموظف / المنتسب المحدد غير موجود' });
        }
        if (user.role !== 'ADMIN') {
          const uDept = user.department;
          const mDept = member.department;
          const deptMatch = (uDept === mDept || db.prepare('SELECT 1 FROM departments WHERE (department_id = ? AND name = ?) OR (department_id = ? AND name = ?)').get(uDept, mDept, mDept, uDept));
          if (!deptMatch) {
            return sendJson(res, 403, { error: 'لا يمكنك إضافة معاملة لمنتسب تابع لقسم آخر.' });
          }
        }
        transactionOwnerId = member.user_id;
        memberUserId = member.user_id;
        transactionDept = member.department || user.department;
      } else {
        // Personal transaction addition check
        if (user.can_add_transaction === 0) {
          return sendJson(res, 403, { error: 'ليس لديك صلاحية لإضافة معاملات جديدة شخصية.' });
        }
      }

      if (!vehicle_numbers || !Array.isArray(vehicle_numbers) || vehicle_numbers.length === 0) {
        return sendJson(res, 400, { error: 'يجب إدخال رقم عجلة واحدة على الأقل' });
      }
      if (!vehicle_images || !Array.isArray(vehicle_images) || vehicle_images.length === 0) {
        return sendJson(res, 400, { error: 'يجب إرفاق صورة واحدة على الأقل للعجلة' });
      }
      if (!receipt_images || !Array.isArray(receipt_images) || receipt_images.length === 0) {
        return sendJson(res, 400, { error: 'يجب إرفاق صورة واحدة على الأقل لوصل الشراء' });
      }

      // Feature 3 & Task 4: Strict vehicle active/deleted and department isolation validation
      for (const plate of vehicle_numbers) {
        const trimmedPlate = String(plate).trim();
        const v = db.prepare('SELECT * FROM vehicles WHERE plate_number = ?').get(trimmedPlate);
        if (v && (v.is_active === 0 || v.is_deleted === 1)) {
          return sendJson(res, 400, { error: 'لا يمكن إضافة صيانة لهذه العجلة لأنها معطلة أو محذوفة' });
        }

        // Strict Department Check for non-Admin
        if (user.role !== 'ADMIN') {
          if (!v) {
            return sendJson(res, 403, { error: 'لا يمكنك تسجيل معاملة لعجلة غير تابعة لقسمك' });
          }
          const userDept = user.department;
          const vehDept = v.department_id;
          const match = (
            vehDept === userDept ||
            db.prepare('SELECT 1 FROM departments WHERE (department_id = ? AND name = ?) OR (department_id = ? AND name = ?)').get(vehDept, userDept, userDept, vehDept)
          );
          if (!match) {
            return sendJson(res, 403, { error: 'لا يمكنك تسجيل معاملة لعجلة غير تابعة لقسمك' });
          }
        } else {
          if (!v) {
            const vehId = 'VEH-' + crypto.randomUUID().slice(0, 6);
            db.prepare('INSERT OR IGNORE INTO vehicles (vehicle_id, plate_number, department_id, is_active, is_deleted, created_at) VALUES (?, ?, ?, 1, 0, ?)').run(
              vehId, trimmedPlate, user.department || null, new Date().toISOString()
            );
          }
        }
      }

      // Feature 2: Maintenance price (Admin only, non-blocking for others)
      let price = 0;
      if (user.role === 'ADMIN') {
        price = parseFloat(body.maintenance_price);
        if (isNaN(price) || price < 0) price = 0;
      }

      // Feature 5: Optional notes field
      const notes = body.notes ? String(body.notes).trim() : '';

      const transactionId = `TX-${new Date().getFullYear()}-${Date.now().toString().slice(-4)}${Math.floor(100 + Math.random() * 900)}`;
      const now = new Date().toISOString();
      const numKm = parseInt(body.current_km, 10) || 0;

      db.prepare(`
        INSERT INTO maintenance_transactions (
          transaction_id, user_id, vehicle_numbers, vehicle_images, receipt_images,
          category, status, is_locked, auditor_note, admin_note, current_km, maintenance_price, notes, is_deleted, submitted_at, audited_by_auditor_at, audited_at,
          department_id, member_user_id, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_AUDITOR', 1, NULL, NULL, ?, ?, ?, 0, ?, NULL, NULL, ?, ?, ?)
      `).run(
        transactionId,
        transactionOwnerId,
        JSON.stringify(vehicle_numbers),
        JSON.stringify(vehicle_images),
        JSON.stringify(receipt_images),
        category || 'صيانة عامة',
        numKm,
        price,
        notes,
        now,
        transactionDept,
        memberUserId,
        user.user_id
      );

      logAudit('CREATE_TRANSACTION', 'transactions', transactionId, user.user_id, user.full_name, {
        member_user_id: memberUserId,
        department_id: transactionDept,
        vehicle_numbers
      });

      const created = db.prepare(`
        SELECT t.*, u.full_name as user_name, u.department, u.unit, u.fcm_token, u.username
        FROM maintenance_transactions t LEFT JOIN users u ON t.user_id = u.user_id
        WHERE t.transaction_id = ?
      `).get(transactionId);

      const formatted = {
        ...created,
        vehicle_numbers: JSON.parse(created.vehicle_numbers),
        vehicle_images: JSON.parse(created.vehicle_images),
        receipt_images: JSON.parse(created.receipt_images),
        current_km: created.current_km || 0,
        maintenance_price: user.role === 'ADMIN' ? (parseFloat(created.maintenance_price) || 0) : 0,
        notes: created.notes || '',
        is_locked: true
      };

      if (user.role !== 'ADMIN') {
        delete formatted.maintenance_price;
      }

      broadcastEvent('NEW_TRANSACTION_FOR_AUDITOR', formatted);

      // Trigger periodic inspection / overdue check (Task 6)
      if (numKm > 0 && vehicle_numbers && vehicle_numbers.length > 0) {
        checkAndTriggerOverdueAlerts(vehicle_numbers[0], numKm, transactionId);
      }

      return sendJson(res, 201, {
        success: true,
        message: 'تم إرسال المعاملة بنجاح إلى مدقق الوصولات للمطابقة والتدقيق',
        transaction: formatted
      });
    }

    const isTxUpdate = (pathname.match(/^\/api\/transactions\/[A-Za-z0-9_-]+$/) && req.method === 'PUT') ||
      (pathname === '/api/transactions/update' && req.method === 'POST');

    if (isTxUpdate) {
      const body = await parseBody(req);
      const parts = pathname.split('/');
      const txId = body.transaction_id || (parts[parts.length - 1] !== 'update' ? parts[parts.length - 1] : null);
      if (!txId) return sendJson(res, 400, { error: 'معرف المعاملة مطلوب' });
      const { vehicle_numbers, vehicle_images, receipt_images, category, current_km, notes, maintenance_price, user_id } = body;

      const tx = db.prepare('SELECT * FROM maintenance_transactions WHERE transaction_id = ?').get(txId);
      if (!tx) return sendJson(res, 404, { error: 'المعاملة غير موجودة' });

      // Determine editing user
      let editor = null;
      if (user_id) {
        editor = db.prepare('SELECT user_id, username, full_name, department, unit, role, is_department_manager, can_edit_dept_transactions, is_read_only FROM users WHERE user_id = ? OR LOWER(username) = LOWER(?)').get(user_id, user_id);
      }
      if (editor && editor.is_read_only === 1) {
        return sendJson(res, 403, { error: 'حسابك مخصص للقراءة والاطلاع فقط، لا تملك صلاحية تعديل المعاملات.' });
      }

      const rawRole = (editor ? editor.role : (body.role || 'USER')) || 'USER';
      const role = rawRole.toUpperCase();

      // Feature 4: RBAC Enforcement
      const isAdmin = role === 'ADMIN';
      const isDeptHead = role === 'DEPARTMENT_HEAD' || (editor && editor.is_department_manager === 1);
      const isFieldUser = !isAdmin && !isDeptHead;

      if (isDeptHead && editor) {
        if (editor.can_edit_dept_transactions === 0 && !isAdmin) {
          return sendJson(res, 403, { error: 'ليس لديك صلاحية تعديل معاملات القسم.' });
        }
        if (tx.user_id !== editor.user_id) {
          const txOwner = db.prepare('SELECT department FROM users WHERE user_id = ?').get(tx.user_id);
          const uDept = editor.department;
          const oDept = txOwner ? txOwner.department : (tx.department_id || '');
          const deptMatch = (uDept === oDept || db.prepare('SELECT 1 FROM departments WHERE (department_id = ? AND name = ?) OR (department_id = ? AND name = ?)').get(uDept, oDept, oDept, uDept));
          if (!deptMatch && !isAdmin) {
            return sendJson(res, 403, { error: 'غير مصرح: يمكنك فقط تعديل معاملات قسمك (' + editor.department + ')' });
          }
        }
      }

      if (isFieldUser && tx.status !== 'IN_PROGRESS') {
        return sendJson(res, 403, {
          error: 'مرفوض رقابياً (HTTP 403 Forbidden): لا يمكن تعديل المعاملة إلا عندما تكون في وضعية (قيد التعديل والمراجعة) بإذن من مدقق الوصولات.'
        });
      }

      let newPrice = tx.maintenance_price;
      if (isAdmin && maintenance_price !== undefined) {
        const p = parseFloat(maintenance_price);
        if (!isNaN(p) && p >= 0) newPrice = p;
      }

      let newStatus = tx.status;
      if (isFieldUser && tx.status === 'IN_PROGRESS') {
        newStatus = 'PENDING_AUDITOR';
      }

      const editorId = editor ? editor.user_id : (isAdmin ? 'admin' : 'system');
      const editorName = editor ? editor.full_name : 'مدير النظام';

      db.prepare(`
        UPDATE maintenance_transactions
        SET vehicle_numbers = COALESCE(?, vehicle_numbers),
            vehicle_images = COALESCE(?, vehicle_images),
            receipt_images = COALESCE(?, receipt_images),
            category = COALESCE(?, category),
            current_km = COALESCE(?, current_km),
            notes = COALESCE(?, notes),
            maintenance_price = ?,
            status = ?,
            updated_by = ?
        WHERE transaction_id = ?
      `).run(
        vehicle_numbers ? JSON.stringify(vehicle_numbers) : null,
        vehicle_images ? JSON.stringify(vehicle_images) : null,
        receipt_images ? JSON.stringify(receipt_images) : null,
        category || null,
        current_km !== undefined ? (parseInt(current_km, 10) || 0) : null,
        notes !== undefined ? String(notes).trim() : null,
        newPrice,
        newStatus,
        editorId,
        txId
      );

      logAudit('UPDATE_TRANSACTION', 'transactions', txId, editorId, editorName, {
        status: newStatus,
        category: category || tx.category
      });

      const updated = db.prepare(`
        SELECT t.*, u.full_name as user_name, u.department, u.unit, u.fcm_token, u.username
        FROM maintenance_transactions t LEFT JOIN users u ON t.user_id = u.user_id
        WHERE t.transaction_id = ?
      `).get(txId);

      const formatted = {
        ...updated,
        vehicle_numbers: JSON.parse(updated.vehicle_numbers),
        vehicle_images: JSON.parse(updated.vehicle_images),
        receipt_images: JSON.parse(updated.receipt_images),
        current_km: updated.current_km || 0,
        maintenance_price: isAdmin ? (parseFloat(updated.maintenance_price) || 0) : 0,
        notes: updated.notes || '',
        is_locked: true
      };

      if (!isAdmin) {
        delete formatted.maintenance_price;
      }

      broadcastEvent('TRANSACTION_EDITED', formatted);

      return sendJson(res, 200, {
        success: true,
        message: 'تم حفظ تعديلات المعاملة بنجاح',
        transaction: formatted
      });
    }

    if (pathname.match(/^\/api\/auditor\/transactions\/[A-Za-z0-9_-]+\/review$/) && req.method === 'POST') {
      const txId = pathname.split('/')[4];
      const body = await parseBody(req);
      const { action, note } = body; // 'APPROVE_TO_ADMIN' or 'RETURN_FOR_EDIT'

      const tx = db.prepare('SELECT * FROM maintenance_transactions WHERE transaction_id = ?').get(txId);
      if (!tx) return sendJson(res, 404, { error: 'المعاملة غير موجودة' });

      let newStatus = '';
      let title = '';
      let message = '';

      if (action === 'APPROVE_TO_ADMIN') {
        newStatus = 'PENDING_ADMIN';
        title = '📋 تم تدقيق الوصولات وإحالتها للأدمن';
        message = `تمت مطابقة وصولات المعاملة ${txId} واعتمادها من مدقق الوصولات وإحالتها للإدارة المركزية (الأدمن) للاعتماد النهائي.` + (note ? ` (ملاحظة المدقق: ${note})` : '');
      } else {
        newStatus = 'IN_PROGRESS';
        title = '🔄 مطلوب تعديل على المعاملة من مدقق الوصولات';
        message = `أعاد مدقق الوصولات المعاملة ${txId} لوضعية قيد المراجعة لتعديلها: ${note || 'يرجى مراجعة وتوضيح الوصولات'}. يمكنك الآن تعديل المعاملة ومرفقاتها.`;
      }

      const now = new Date().toISOString();

      db.prepare(`
        UPDATE maintenance_transactions
        SET status = ?, auditor_note = ?, audited_by_auditor_at = ?
        WHERE transaction_id = ?
      `).run(newStatus, note || null, action === 'APPROVE_TO_ADMIN' ? now : null, txId);

      const updated = db.prepare(`
        SELECT t.*, u.full_name as user_name, u.department, u.unit, u.fcm_token, u.username
        FROM maintenance_transactions t LEFT JOIN users u ON t.user_id = u.user_id
        WHERE t.transaction_id = ?
      `).get(txId);

      // Create notification for user
      const notifId = 'NOTIF-' + crypto.randomUUID().slice(0, 8);
      db.prepare(`
        INSERT INTO notifications (notification_id, user_id, transaction_id, title, message, type, is_read, created_at)
        VALUES (?, ?, ?, ?, ?, 'AUDITOR_DECISION', 0, ?)
      `).run(notifId, updated.user_id, txId, title, message, now);

      broadcastEvent('AUDITOR_DECISION_UPDATED', {
        transaction: {
          ...updated,
          vehicle_numbers: JSON.parse(updated.vehicle_numbers),
          vehicle_images: JSON.parse(updated.vehicle_images),
          receipt_images: JSON.parse(updated.receipt_images),
          is_locked: true
        },
        notification: {
          notification_id: notifId,
          user_id: updated.user_id,
          title,
          message,
          status: newStatus,
          created_at: now
        }
      });

      return sendJson(res, 200, {
        success: true,
        message: action === 'APPROVE_TO_ADMIN' ? 'تمت إحالة المعاملة بنجاح إلى الإدارة المركزية (الأدمن)' : 'تمت إعادة المعاملة للمستخدم الميداني للتعديل',
        transaction: updated
      });
    }

    
    // --------------------------------------------------------------------------
    // Admin Update Transaction Amount (مبلغ الصيانة)
    // --------------------------------------------------------------------------
    const isAmountRoute = (
      pathname === '/api/admin/transactions/update-amount' ||
      pathname.match(/^\/api\/admin\/transactions\/[A-Za-z0-9_-]+\/amount$/) ||
      pathname.match(/^\/api\/transactions\/[A-Za-z0-9_-]+\/maintenance-amount$/) ||
      pathname.match(/^\/api\/transactions\/[A-Za-z0-9_-]+\/amount$/)
    ) && (req.method === 'POST' || req.method === 'PATCH' || req.method === 'PUT');

    if (isAmountRoute) {
      const body = await parseBody(req);
      if (!checkIsAdmin(req, parsedUrl, body)) {
        return sendJson(res, 403, {
          error: 'صلاحية مرفوضة: تعديل مبلغ الصيانة محصور بمدير النظام فقط (403 Forbidden)'
        });
      }

      let txId = (body.transaction_id || '').trim();
      if (!txId) {
        const parts = pathname.split('/');
        txId = parts[parts.length - 2].startsWith('TX-') ? parts[parts.length - 2] : (parts[parts.length - 1].startsWith('TX-') ? parts[parts.length - 1] : parts[parts.length - 2]);
        if (!txId.startsWith('TX-') && parts.length >= 5) {
          txId = parts[4].startsWith('TX-') ? parts[4] : parts[3];
        }
      }
      const amountVal = parseFloat(
        body.maintenance_amount !== undefined ? body.maintenance_amount :
        (body.maintenance_price !== undefined ? body.maintenance_price : body.amount)
      );

      if (!txId) {
        return sendJson(res, 400, { error: 'معرف المعاملة مطلوب' });
      }
      if (isNaN(amountVal) || amountVal <= 0) {
        return sendJson(res, 400, { error: 'يرجى إدخال مبلغ الصيانة قبل الاعتماد النهائي (يجب أن يكون أكبر من صفر)' });
      }

      const tx = db.prepare('SELECT * FROM maintenance_transactions WHERE transaction_id = ?').get(txId);
      if (!tx) {
        return sendJson(res, 404, { error: 'المعاملة غير موجودة' });
      }

      db.prepare('UPDATE maintenance_transactions SET maintenance_price = ? WHERE transaction_id = ?').run(amountVal, txId);

      const updated = db.prepare(`
        SELECT t.*, u.full_name as user_name, u.department, u.unit, u.fcm_token, u.username
        FROM maintenance_transactions t LEFT JOIN users u ON t.user_id = u.user_id
        WHERE t.transaction_id = ?
      `).get(txId);

      broadcastEvent('TRANSACTION_UPDATED', {
        transaction_id: txId,
        maintenance_price: amountVal,
        transaction: {
          ...updated,
          vehicle_numbers: JSON.parse(updated.vehicle_numbers || '[]'),
          vehicle_images: JSON.parse(updated.vehicle_images || '[]'),
          receipt_images: JSON.parse(updated.receipt_images || '[]'),
          is_locked: true
        }
      });

      return sendJson(res, 200, {
        success: true,
        transaction_id: txId,
        maintenance_price: amountVal,
        message: 'تم تحديث وحفظ مبلغ الصيانة بنجاح'
      });
    }

    // --------------------------------------------------------------------------
    // Admin Update Transaction KM (قراءة العداد) with Audit Log & Fleet Sync
    // --------------------------------------------------------------------------
    const isKmRoute = (
      pathname === '/api/admin/transactions/update-km' ||
      pathname.match(/^\/api\/admin\/transactions\/[A-Za-z0-9_-]+\/km$/) ||
      pathname.match(/^\/api\/transactions\/[A-Za-z0-9_-]+\/km$/) ||
      pathname.match(/^\/api\/transactions\/[A-Za-z0-9_-]+\/current-km$/)
    ) && (req.method === 'POST' || req.method === 'PATCH' || req.method === 'PUT');

    if (isKmRoute) {
      const body = await parseBody(req);
      if (!checkIsAdmin(req, parsedUrl, body)) {
        return sendJson(res, 403, {
          error: 'صلاحية مرفوضة: تعديل قراءة العداد محصور بمدير النظام فقط (403 Forbidden)'
        });
      }

      let txId = (body.transaction_id || '').trim();
      if (!txId) {
        const parts = pathname.split('/');
        txId = parts[parts.length - 2].startsWith('TX-') ? parts[parts.length - 2] : (parts[parts.length - 1].startsWith('TX-') ? parts[parts.length - 1] : parts[parts.length - 2]);
        if (!txId.startsWith('TX-') && parts.length >= 5) {
          txId = parts[4].startsWith('TX-') ? parts[4] : parts[3];
        }
      }
      const newKm = parseInt(
        body.new_km !== undefined ? body.new_km :
        (body.current_km !== undefined ? body.current_km : body.km),
        10
      );
      const reason = (body.reason || 'تصحيح خطأ إدخال بواسطة مدير النظام').trim();
      const adminId = (body.admin_id || 'admin').trim();
      const adminName = (body.admin_name || 'مدير النظام').trim();

      if (!txId) {
        return sendJson(res, 400, { error: 'معرف المعاملة مطلوب' });
      }
      if (isNaN(newKm) || newKm <= 0) {
        return sendJson(res, 400, { error: 'يرجى إدخال قراءة عداد صحيحة وموجبة (أكبر من صفر)' });
      }

      const tx = db.prepare('SELECT * FROM maintenance_transactions WHERE transaction_id = ?').get(txId);
      if (!tx) {
        return sendJson(res, 404, { error: 'المعاملة غير موجودة' });
      }

      const oldKm = tx.current_km || 0;
      const now = new Date().toISOString();

      db.prepare('UPDATE maintenance_transactions SET current_km = ? WHERE transaction_id = ?').run(newKm, txId);

      db.prepare(`
        INSERT INTO km_audit_logs (transaction_id, old_km, new_km, admin_id, admin_name, timestamp, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(txId, oldKm, newKm, adminId, adminName, now, reason);

      const updated = db.prepare(`
        SELECT t.*, u.full_name as user_name, u.department, u.unit, u.fcm_token, u.username
        FROM maintenance_transactions t LEFT JOIN users u ON t.user_id = u.user_id
        WHERE t.transaction_id = ?
      `).get(txId);

      broadcastEvent('TRANSACTION_UPDATED', {
        transaction_id: txId,
        current_km: newKm,
        old_km: oldKm,
        transaction: {
          ...updated,
          vehicle_numbers: JSON.parse(updated.vehicle_numbers || '[]'),
          vehicle_images: JSON.parse(updated.vehicle_images || '[]'),
          receipt_images: JSON.parse(updated.receipt_images || '[]'),
          is_locked: true
        }
      });

      return sendJson(res, 200, {
        success: true,
        transaction_id: txId,
        old_km: oldKm,
        new_km: newKm,
        message: 'تم تصحيح وتحديث قراءة العداد وتوثيقها في سجل التدقيق بنجاح'
      });
    }

    // --------------------------------------------------------------------------
    // Admin Get Transaction KM Audit History
    // --------------------------------------------------------------------------
    if (pathname.match(/^\/api\/admin\/transactions\/[A-Za-z0-9_-]+\/km-audit$/) && req.method === 'GET') {
      const txId = pathname.split('/')[4];
      const logs = db.prepare('SELECT * FROM km_audit_logs WHERE transaction_id = ? ORDER BY datetime(timestamp) DESC').all(txId);
      return sendJson(res, 200, { transaction_id: txId, logs });
    }

    // --------------------------------------------------------------------------
    // 10. Admin Final Decision (المطلب 1)
    // --------------------------------------------------------------------------
    if (pathname.match(/^\/api\/admin\/transactions\/[A-Za-z0-9_-]+\/status$/) && req.method === 'POST') {
      const txId = pathname.split('/')[4];
      const body = await parseBody(req);
      const { status, admin_note, maintenance_price } = body;

      const tx = db.prepare('SELECT * FROM maintenance_transactions WHERE transaction_id = ?').get(txId);
      if (!tx) return sendJson(res, 404, { error: 'المعاملة غير موجودة' });

      const auditedAt = status === 'AUDITED' ? new Date().toISOString() : tx.audited_at;

      let price = tx.maintenance_price;
      if (maintenance_price !== undefined) {
        const p = parseFloat(maintenance_price);
        if (!isNaN(p) && p >= 0) price = p;
      }

      if (status === 'AUDITED') {
        if (!price || price <= 0) {
          return sendJson(res, 400, {
            error: 'يرجى إدخال مبلغ الصيانة قبل الاعتماد النهائي (يجب أن يكون أكبر من صفر)'
          });
        }
      }

      db.prepare(`
        UPDATE maintenance_transactions
        SET status = ?, admin_note = COALESCE(?, admin_note), maintenance_price = ?, audited_at = ?
        WHERE transaction_id = ?
      `).run(status, admin_note || null, price, auditedAt, txId);

      const updated = db.prepare(`
        SELECT t.*, u.full_name as user_name, u.department, u.unit, u.fcm_token, u.username
        FROM maintenance_transactions t LEFT JOIN users u ON t.user_id = u.user_id
        WHERE t.transaction_id = ?
      `).get(txId);

      const notifId = 'NOTIF-' + crypto.randomUUID().slice(0, 8);
      const statusTitle = status === 'AUDITED' ? '✅ تم الاعتماد النهائي والصرف من الإدارة' : '⏳ المعاملة قيد تدقيق الإدارة';
      const statusMsg = `المعاملة ${txId}: ` + (admin_note || 'تم اعتماد المعاملة نهائياً.');

      db.prepare(`
        INSERT INTO notifications (notification_id, user_id, transaction_id, title, message, type, is_read, created_at)
        VALUES (?, ?, ?, ?, ?, 'ADMIN_DECISION', 0, ?)
      `).run(notifId, updated.user_id, txId, statusTitle, statusMsg, new Date().toISOString());

      broadcastEvent('TRANSACTION_STATUS_UPDATED', {
        transaction: {
          ...updated,
          vehicle_numbers: JSON.parse(updated.vehicle_numbers),
          vehicle_images: JSON.parse(updated.vehicle_images),
          receipt_images: JSON.parse(updated.receipt_images),
          is_locked: true
        },
        notification: {
          notification_id: notifId,
          user_id: updated.user_id,
          title: statusTitle,
          message: statusMsg,
          status,
          created_at: new Date().toISOString()
        }
      });

      return sendJson(res, 200, {
        success: true,
        message: 'تم تحديث قرار الإدارة بنجاح',
        transaction: updated
      });
    }

    // --------------------------------------------------------------------------
    // 11. Analytics Endpoint
    // --------------------------------------------------------------------------
    if (pathname === '/api/admin/analytics' && req.method === 'GET') {
      const totalTx = db.prepare('SELECT COUNT(*) as count FROM maintenance_transactions').get().count;
      const pendingAuditor = db.prepare("SELECT COUNT(*) as count FROM maintenance_transactions WHERE status = 'PENDING_AUDITOR'").get().count;
      const inProgress = db.prepare("SELECT COUNT(*) as count FROM maintenance_transactions WHERE status = 'IN_PROGRESS'").get().count;
      const pendingAdmin = db.prepare("SELECT COUNT(*) as count FROM maintenance_transactions WHERE status = 'PENDING_ADMIN'").get().count;
      const audited = db.prepare("SELECT COUNT(*) as count FROM maintenance_transactions WHERE status = 'AUDITED'").get().count;
      const totalUsers = db.prepare("SELECT COUNT(*) as count FROM users").get().count;

      const allTx = db.prepare('SELECT vehicle_numbers, category FROM maintenance_transactions').all();
      const vehicleStats = {};
      for (const row of allTx) {
        try {
          const numbers = JSON.parse(row.vehicle_numbers);
          for (const num of numbers) {
            const trimmed = num.trim();
            if (!vehicleStats[trimmed]) {
              vehicleStats[trimmed] = { vehicle_number: trimmed, count: 0, categories: {} };
            }
            vehicleStats[trimmed].count++;
            vehicleStats[trimmed].categories[row.category] = (vehicleStats[trimmed].categories[row.category] || 0) + 1;
          }
        } catch (e) {}
      }

      const topVehicles = Object.values(vehicleStats)
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      return sendJson(res, 200, {
        total: totalTx,
        pending_auditor: pendingAuditor,
        in_progress: inProgress,
        pending_admin: pendingAdmin,
        audited,
        total_users: totalUsers,
        top_faulty_vehicles: topVehicles
      });
    }

    // Notifications
    if (pathname.match(/^\/api\/notifications\/[A-Za-z0-9_-]+\/seen-by$/) && req.method === 'GET') {
      const parts = pathname.split('/');
      const notifId = parts[3];
      const receipts = db.prepare(`
        SELECT r.id, r.notification_id, r.user_id, r.seen_at, r.sync_status,
               COALESCE(r.user_name, u.full_name, u.username, 'مستخدم') as user_name,
               u.username, u.department, u.role
        FROM notification_read_receipts r
        LEFT JOIN users u ON r.user_id = u.user_id
        WHERE r.notification_id = ?
        ORDER BY datetime(r.seen_at) DESC
      `).all(notifId);

      const allActiveUsers = db.prepare(`
        SELECT user_id, username, full_name, department, role
        FROM users
        WHERE is_active = 1 AND (is_deleted = 0 OR is_deleted IS NULL)
      `).all();

      const seenUserIds = new Set(receipts.map(r => r.user_id));
      const unseenUsers = allActiveUsers.filter(u => !seenUserIds.has(u.user_id));

      return sendJson(res, 200, {
        notification_id: notifId,
        total_users: allActiveUsers.length,
        seen_count: receipts.length,
        unseen_count: unseenUsers.length,
        seen_users: receipts,
        unseen_users: unseenUsers
      });
    }

    if (pathname === '/api/notifications/receipts/record' && req.method === 'POST') {
      const body = await parseBody(req);
      const { notification_id, user_id, user_name, seen_at } = body;
      if (!notification_id || !user_id) {
        return sendJson(res, 400, { error: 'notification_id و user_id حقول مطلوبة' });
      }

      const receiptId = 'NRR-' + crypto.randomUUID().slice(0, 8);
      const now = seen_at || new Date().toISOString();
      const uName = user_name || (db.prepare('SELECT full_name FROM users WHERE user_id = ?').get(user_id)?.full_name || '');

      db.prepare(`
        INSERT OR REPLACE INTO notification_read_receipts (id, notification_id, user_id, user_name, seen_at, sync_status, created_at)
        VALUES (?, ?, ?, ?, ?, 'SYNCED', ?)
      `).run(receiptId, notification_id, user_id, uName, now, new Date().toISOString());

      // Mark as read in notifications table if targeting this user
      try {
        db.prepare('UPDATE notifications SET is_read = 1 WHERE notification_id = ? AND user_id = ?').run(notification_id, user_id);
      } catch(e) {}

      broadcastEvent('NOTIFICATION_SEEN', {
        notification_id,
        user_id,
        user_name: uName,
        seen_at: now
      });

      return sendJson(res, 200, { success: true, message: 'تم تسجيل تأكيد القراءة بنجاح' });
    }

    if ((pathname === '/api/notifications' || pathname.startsWith('/api/notifications/')) && req.method === 'GET') {
      const parts = pathname.replace('/api/notifications', '').replace(/^\//, '');
      const userId = parts || parsedUrl.searchParams.get('user_id');
      let query = 'SELECT * FROM notifications';
      const params = [];
      if (userId && userId !== 'ALL') {
        query += ' WHERE user_id = ?';
        params.push(userId);
      }
      query += ' ORDER BY datetime(created_at) DESC LIMIT 50';
      const notifications = db.prepare(query).all(...params);
      return sendJson(res, 200, { notifications });
    }

    if (pathname === '/api/notifications/mark-read' && req.method === 'POST') {
      const body = await parseBody(req);
      if (body.user_id) {
        db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(body.user_id);
      }
      return sendJson(res, 200, { success: true });
    }

    // --------------------------------------------------------------------------
    // Admin Audit Logs Endpoint
    // --------------------------------------------------------------------------
    if (pathname === '/api/admin/audit-logs' && req.method === 'GET') {
      const logs = db.prepare('SELECT * FROM audit_logs ORDER BY datetime(timestamp) DESC LIMIT 200').all();
      return sendJson(res, 200, { success: true, count: logs.length, logs });
    }

    // --------------------------------------------------------------------------
    // Full System Backup & Restore Endpoints (Module 5)
    // --------------------------------------------------------------------------
    if (pathname === '/api/admin/backup' && req.method === 'GET') {
      const backupTables = [
        'departments',
        'users',
        'vehicles',
        'maintenance_categories',
        'maintenance_transactions',
        'maintenance_requests',
        'deleted_records',
        'notifications',
        'notification_read_receipts',
        'audit_logs',
        'system_settings',
        'login_history'
      ];

      const backupData = {};
      const counts = {};

      for (const t of backupTables) {
        try {
          const rows = db.prepare(`SELECT * FROM ${t}`).all();
          backupData[t] = rows;
          counts[t] = rows.length;
        } catch(e) {
          backupData[t] = [];
          counts[t] = 0;
        }
      }

      const now = new Date();
      const YYYY = now.getFullYear();
      const MM = String(now.getMonth() + 1).padStart(2, '0');
      const DD = String(now.getDate()).padStart(2, '0');
      const HH = String(now.getHours()).padStart(2, '0');
      const mm = String(now.getMinutes()).padStart(2, '0');
      const filename = `wheel_maintenance_backup_${YYYY}-${MM}-${DD}_${HH}-${mm}.json`;

      const payload = {
        meta: {
          app_version: "v7.2",
          backup_date: now.toISOString(),
          exported_by: "المدير العام (الأدمن)",
          record_counts: counts
        },
        data: backupData
      };

      logAudit('BACKUP_DOWNLOAD', 'system', 'all', 'admin', 'المدير العام', { filename, record_counts: counts });

      const jsonBuf = Buffer.from(JSON.stringify(payload, null, 2), 'utf8');

      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Access-Control-Allow-Origin': req.headers.origin || '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Content-Length': jsonBuf.length
      });
      return res.end(jsonBuf);
    }

    if (pathname === '/api/admin/restore' && req.method === 'POST') {
      const body = await parseBody(req);
      if (!body || !body.data || typeof body.data !== 'object') {
        return sendJson(res, 400, { error: 'ملف النسخة الاحتياطية غير صالح أو تالف (Missing data object)' });
      }

      const { departments, users, vehicles, maintenance_transactions } = body.data;
      if (!Array.isArray(departments) || !Array.isArray(users) || !Array.isArray(vehicles) || !Array.isArray(maintenance_transactions)) {
        return sendJson(res, 400, { error: 'ملف النسخة الاحتياطية غير صالح أو تالف (Required tables missing)' });
      }

      // 1. Create server-side pre-restore backup
      try {
        const preRestoreBackup = {};
        for (const t of ['departments', 'users', 'vehicles', 'maintenance_categories', 'maintenance_transactions', 'maintenance_requests', 'deleted_records', 'notification_read_receipts', 'audit_logs']) {
          preRestoreBackup[t] = db.prepare(`SELECT * FROM ${t}`).all();
        }
        const safetyPath = path.join(__dirname, 'data', `pre_restore_safety_backup_${Date.now()}.json`);
        fs.writeFileSync(safetyPath, JSON.stringify(preRestoreBackup, null, 2), 'utf8');
      } catch(safetyErr) {
        console.warn('Pre-restore safety backup warning:', safetyErr);
      }

      // 2. Perform atomic restore inside transaction
      db.exec('PRAGMA foreign_keys = OFF;');
      db.exec('BEGIN TRANSACTION;');
      const restoredCounts = {};
      try {
        const order = [
          'departments',
          'users',
          'vehicles',
          'maintenance_categories',
          'maintenance_transactions',
          'maintenance_requests',
          'deleted_records',
          'notifications',
          'notification_read_receipts',
          'audit_logs',
          'system_settings',
          'login_history'
        ];

        for (const t of order) {
          const rows = body.data[t];
          if (Array.isArray(rows)) {
            db.exec(`DELETE FROM ${t};`);
            if (rows.length > 0) {
              const cols = Object.keys(rows[0]);
              const placeholders = cols.map(() => '?').join(', ');
              const insertStmt = db.prepare(`INSERT INTO ${t} (${cols.join(', ')}) VALUES (${placeholders})`);
              for (const row of rows) {
                const vals = cols.map(c => row[c] !== undefined ? row[c] : null);
                insertStmt.run(...vals);
              }
            }
            restoredCounts[t] = rows.length;
          }
        }

        db.exec('COMMIT;');
        db.exec('PRAGMA foreign_keys = ON;');
      } catch (restoreErr) {
        db.exec('ROLLBACK;');
        db.exec('PRAGMA foreign_keys = ON;');
        console.error('Database restore error:', restoreErr);
        return sendJson(res, 500, { error: 'فشلت عملية استعادة قاعدة البيانات: ' + restoreErr.message });
      }

      logAudit('SYSTEM_RESTORE', 'system', 'all', 'admin', 'المدير العام', { restored_counts: restoredCounts });
      broadcastEvent('DATABASE_RESTORED', { timestamp: new Date().toISOString(), counts: restoredCounts });
      return sendJson(res, 200, {
        success: true,
        message: 'تمت استعادة كافة البيانات بنجاح من النسخة الاحتياطية ✅',
        restored_counts: restoredCounts
      });
    }

    // --------------------------------------------------------------------------
    // Styled Excel Export Endpoint (Module 2 Part B)
    // --------------------------------------------------------------------------
    if (pathname === '/api/export/excel' && req.method === 'POST') {
      const body = await parseBody(req);
      const title = body.title;
      const subtitle = body.subtitle;
      const columns = body.columns || body.headers;
      const rows = body.rows;
      const totals = body.totals;
      const filename = body.filename;

      if (!columns || !Array.isArray(columns) || !rows || !Array.isArray(rows)) {
        return sendJson(res, 400, { error: 'بيانات التصدير غير مكتملة' });
      }

      const wb = XLSX.utils.book_new();
      const colCount = columns.length;
      const aoa = [];

      aoa.push([title || 'جدول البيانات']);
      aoa.push([subtitle || (`تاريخ التصدير: ${new Date().toLocaleString('ar-IQ')} | إجمالي السجلات: ${rows.length}`)]);
      aoa.push([]);
      aoa.push(columns.map(c => (typeof c === 'object' ? c.title : c)));

      rows.forEach(r => {
        aoa.push(Array.isArray(r) ? r : Object.values(r));
      });

      if (totals && Array.isArray(totals) && totals.length > 0) {
        aoa.push(totals);
      }

      const ws = XLSX.utils.aoa_to_sheet(aoa);
      ws['!views'] = [{ rightToLeft: true }];
      ws['!merges'] = [
        { s: { r: 0, c: 0 }, e: { r: 0, c: colCount - 1 } },
        { s: { r: 1, c: 0 }, e: { r: 1, c: colCount - 1 } }
      ];
      ws['!cols'] = columns.map(c => ({ wch: (typeof c === 'object' && c.width) ? c.width : 20 }));

      XLSX.utils.book_append_sheet(wb, ws, 'البيانات المصدرة');
      const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

      const outName = filename || `تصدير_بيانات_${Date.now()}.xlsx`;
      res.writeHead(200, {
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': `attachment; filename="${encodeURIComponent(outName)}"`,
        'Access-Control-Allow-Origin': req.headers.origin || '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Content-Length': buf.length
      });
      return res.end(buf);
    }

    // --------------------------------------------------------------------------
    // Static Assets
    // --------------------------------------------------------------------------
    let safePath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
    if (safePath === '/' || safePath === '\\') {
      safePath = '/index.html';
    }

    const localFilePath = path.join(__dirname, 'public', safePath);

    if (fs.existsSync(localFilePath) && fs.statSync(localFilePath).isFile()) {
      return serveStatic(req, res, localFilePath);
    } else {
      const indexPath = path.join(__dirname, 'public', 'index.html');
      if (fs.existsSync(indexPath)) {
        return serveStatic(req, res, indexPath);
      }
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
    }

  } catch (err) {
    console.error('Server error:', err);
    return sendJson(res, 500, { error: 'Internal Server Error: ' + err.message });
  }
});

server.listen(PORT, () => {
  console.log(`================================================================`);
  console.log(`  نظام إدارة وتوثيق مشتريات وصيانة العجلات (v2.0 المحدث)`);
  console.log(`  الخادم يعمل على: http://localhost:${PORT}`);
  console.log(`================================================================`);
});
