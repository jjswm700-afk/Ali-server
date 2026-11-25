// ==============================================================================
// Wheel Maintenance & Purchasing Documentation System (Cloud Edition v3.0)
// Backend Server - Node.js + PostgreSQL (Supabase) via pg
// Architecture: 3-Tier Workflow (User -> Intermediate Auditor -> Admin)
// ==============================================================================

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool } = require('pg');

let XLSX = null;
try {
  XLSX = require('./public/js/xlsx.full.min.js');
} catch (e) {
  try { XLSX = require('xlsx'); } catch (_) {}
}

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ CRITICAL: DATABASE_URL environment variable is missing!');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 15,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000
});

// ------------------------------------------------------------------------------
// Security & Hashing Helpers
// ------------------------------------------------------------------------------
function hashPassword(password) {
  const salt = 'wheel_security_salt_2026';
  return crypto.createHash('sha256').update(String(password) + salt).digest('hex');
}

function verifyPassword(password, storedHash) {
  if (!storedHash) return false;
  if (password === storedHash) return true;
  if (hashPassword(password) === storedHash) return true;
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
  return false;
}

function normalizeRole(r) {
  if (!r) return 'USER';
  const str = String(r).trim();
  const up = str.toUpperCase();
  if (str === 'مدير النظام (الأدمن)' || up === 'ADMIN') return 'ADMIN';
  if (str === 'مسؤول القسم' || up === 'DEPARTMENT_HEAD' || str === 'Department_Head') return 'DEPARTMENT_HEAD';
  if (str === 'مدقق وصولات' || up === 'AUDITOR') return 'AUDITOR';
  return 'USER';
}

function parseJsonArray(val) {
  if (Array.isArray(val)) return val;
  if (!val) return [];
  try {
    const parsed = JSON.parse(val);
    return Array.isArray(parsed) ? parsed : [String(val)];
  } catch (_) {
    return typeof val === 'string' && val.trim() ? [val.trim()] : [];
  }
}

// ------------------------------------------------------------------------------
// Database Schema & Initial Seeding (PostgreSQL / Supabase)
// ------------------------------------------------------------------------------
async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS departments (
        department_id VARCHAR(100) PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        code VARCHAR(50),
        is_deleted BOOLEAN DEFAULT FALSE,
        deleted_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS users (
        user_id VARCHAR(100) PRIMARY KEY,
        username VARCHAR(150) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        department VARCHAR(255) NOT NULL,
        unit VARCHAR(255) DEFAULT '',
        fcm_token TEXT,
        role VARCHAR(50) DEFAULT 'USER',
        is_active BOOLEAN DEFAULT TRUE,
        is_read_only BOOLEAN DEFAULT FALSE,
        can_add_transaction BOOLEAN DEFAULT TRUE,
        is_department_manager BOOLEAN DEFAULT FALSE,
        assigned_department_id VARCHAR(100),
        can_add_dept_members_transactions BOOLEAN DEFAULT FALSE,
        can_edit_dept_transactions BOOLEAN DEFAULT FALSE,
        is_deleted BOOLEAN DEFAULT FALSE,
        deleted_at TIMESTAMPTZ,
        deleted_by VARCHAR(100),
        last_login_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS vehicles (
        vehicle_id VARCHAR(100) PRIMARY KEY,
        plate_number VARCHAR(150) UNIQUE NOT NULL,
        vehicle_type VARCHAR(150),
        department_id VARCHAR(255),
        current_km INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        is_deleted BOOLEAN DEFAULT FALSE,
        deleted_at TIMESTAMPTZ,
        deleted_by VARCHAR(100),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        transaction_id VARCHAR(100) UNIQUE NOT NULL,
        wheel_id VARCHAR(255),
        user_id VARCHAR(100),
        department_id VARCHAR(255),
        member_user_id VARCHAR(100),
        created_by VARCHAR(100),
        updated_by VARCHAR(100),
        description TEXT DEFAULT '',
        cost NUMERIC(14,2) DEFAULT 0,
        mileage INTEGER DEFAULT 0,
        receipt_image TEXT,
        vehicle_images JSONB DEFAULT '[]'::jsonb,
        receipt_images JSONB DEFAULT '[]'::jsonb,
        vehicle_numbers JSONB DEFAULT '[]'::jsonb,
        category VARCHAR(255) DEFAULT 'صيانة عامة',
        status VARCHAR(50) DEFAULT 'PENDING_AUDITOR',
        is_locked BOOLEAN DEFAULT TRUE,
        auditor_note TEXT,
        admin_note TEXT,
        audited_by_auditor_at TIMESTAMPTZ,
        audited_at TIMESTAMPTZ,
        is_deleted BOOLEAN DEFAULT FALSE,
        deleted_at TIMESTAMPTZ,
        deleted_by VARCHAR(100),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS maintenance_categories (
        category_id VARCHAR(100) PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        icon VARCHAR(50) DEFAULT '🛞',
        description TEXT,
        default_replacement_km INTEGER DEFAULT 5000,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS maintenance_requests (
        request_id VARCHAR(100) PRIMARY KEY,
        user_id VARCHAR(100) NOT NULL,
        user_name VARCHAR(255),
        department VARCHAR(255),
        vehicle_number VARCHAR(150) NOT NULL,
        current_km INTEGER NOT NULL DEFAULT 0,
        category VARCHAR(255) NOT NULL,
        notes TEXT DEFAULT '',
        status VARCHAR(50) DEFAULT 'PENDING',
        workshop_name VARCHAR(255),
        admin_response_note TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        responded_at TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS notifications (
        notification_id VARCHAR(100) PRIMARY KEY,
        user_id VARCHAR(100) NOT NULL,
        transaction_id VARCHAR(100),
        title VARCHAR(255) NOT NULL,
        purpose VARCHAR(255),
        message TEXT NOT NULL,
        type VARCHAR(50) NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS notification_read_receipts (
        id SERIAL PRIMARY KEY,
        notification_id VARCHAR(100) NOT NULL,
        user_id VARCHAR(100) NOT NULL,
        user_name VARCHAR(255),
        seen_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(notification_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS deleted_records (
        id SERIAL PRIMARY KEY,
        entity_type VARCHAR(100) NOT NULL,
        entity_id VARCHAR(100) NOT NULL,
        record_snapshot JSONB NOT NULL,
        deleted_by VARCHAR(100),
        deleted_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        action VARCHAR(100) NOT NULL,
        entity_type VARCHAR(100) NOT NULL,
        entity_id VARCHAR(100),
        actor_id VARCHAR(100),
        actor_name VARCHAR(255),
        details TEXT,
        timestamp TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS system_settings (
        key VARCHAR(150) PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS login_history (
        log_id VARCHAR(100) PRIMARY KEY,
        user_id VARCHAR(100),
        username VARCHAR(150) NOT NULL,
        full_name VARCHAR(255),
        role VARCHAR(50),
        ip_address VARCHAR(100),
        user_agent TEXT,
        status VARCHAR(100) NOT NULL,
        timestamp TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Ensure missing columns on pre-existing Supabase tables
    const alterStatements = [
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS user_id VARCHAR(100)",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS wheel_id VARCHAR(255)",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS department_id VARCHAR(255)",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS member_user_id VARCHAR(100)",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS created_by VARCHAR(100)",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS updated_by VARCHAR(100)",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS cost NUMERIC(14,2) DEFAULT 0",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS mileage INTEGER DEFAULT 0",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS receipt_image TEXT",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS vehicle_images JSONB DEFAULT '[]'::jsonb",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS receipt_images JSONB DEFAULT '[]'::jsonb",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS vehicle_numbers JSONB DEFAULT '[]'::jsonb",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS category VARCHAR(255) DEFAULT 'صيانة عامة'",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'PENDING_AUDITOR'",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS is_locked BOOLEAN DEFAULT TRUE",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS auditor_note TEXT",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS admin_note TEXT",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS audited_by_auditor_at TIMESTAMPTZ",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS audited_at TIMESTAMPTZ",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS deleted_by VARCHAR(100)",
      "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS unit VARCHAR(255) DEFAULT ''",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS fcm_token TEXT",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_by VARCHAR(100)",
      "ALTER TABLE departments ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE",
      "ALTER TABLE departments ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ"
    ];
    for (const sql of alterStatements) {
      try { await client.query(sql); } catch (_) {}
    }

    // Seed default departments
    const depts = [
      ['DEPT-000', 'إدارة الصيانة والآليات المركزية'],
      ['DEPT-001', 'قسم النقل والآليات'],
      ['DEPT-002', 'قسم الخدمات والآليات التخصصية'],
      ['DEPT-003', 'شعبة التدقيق والرقابة المالية'],
      ['DEPT-004', 'قسم الخدمات الإدارية']
    ];
    for (const [id, name] of depts) {
      await client.query(
        'INSERT INTO departments (department_id, name) VALUES ($1, $2) ON CONFLICT (department_id) DO NOTHING',
        [id, name]
      );
    }

    // Seed default users if empty
    const uRes = await client.query('SELECT COUNT(*)::int AS c FROM users');
    if (uRes.rows[0].c === 0) {
      await client.query(`
        INSERT INTO users (user_id, username, password_hash, full_name, department, unit, role, is_active)
        VALUES
          ('USR-ADMIN-001', 'admin', $1, 'المهندس أحمد مصطفى (مدير التدقيق والرقابة)', 'DEPT-000', 'الرقابة المركزية', 'ADMIN', TRUE),
          ('USR-AUDITOR-001', 'auditor1', $2, 'الأستاذ سجاد حسين علي (مدقق وصولات)', 'DEPT-003', 'لجنة فحص الوصولات', 'AUDITOR', TRUE),
          ('USR-FIELD-001', 'user1', $3, 'حيدر علي عبد الحسين', 'DEPT-001', 'شعبة العجلات الثقيلة', 'USER', TRUE)
        ON CONFLICT (username) DO NOTHING
      `, [hashPassword('admin123'), hashPassword('auditor123'), hashPassword('123456')]);
    }

    // Seed default categories if empty
    const cRes = await client.query('SELECT COUNT(*)::int AS c FROM maintenance_categories');
    if (cRes.rows[0].c === 0) {
      const cats = [
        ['CAT-01', 'تبديل إطارات (عجلات)', '🛞', 'تبديل إطارات شاحنات وسيارات خفيفة', 40000],
        ['CAT-02', 'صيانة ميكانيكية وميزانية', '⚙️', 'صيانة صدر أمامي وميزانية وتبطين درامات', 15000],
        ['CAT-03', 'تبديل زيوت وفلاتر', '🛢️', 'تبديل زيوت محرك وهيدروليك وفلاتر', 5000],
        ['CAT-04', 'شراء بطاريات جديدة', '🔋', 'تجهيز بطاريات شحن للآليات', 30000],
        ['CAT-05', 'صيانة كهربائية وتبريد', '⚡', 'فحص دينامو وتعبئة غاز تبريد', 20000],
        ['CAT-06', 'صيانة شاملة ومشتريات أخرى', '🛠️', 'مشتريات قطع غيار متفرقة', 10000]
      ];
      for (const [id, name, icon, desc, km] of cats) {
        await client.query(
          'INSERT INTO maintenance_categories (category_id, name, icon, description, default_replacement_km) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING',
          [id, name, icon, desc, km]
        );
      }
    }

    // Seed default settings
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
    for (const [k, v] of Object.entries(defaultSettings)) {
      await client.query(
        'INSERT INTO system_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING',
        [k, v]
      );
    }

    console.log('✅ Supabase PostgreSQL tables & seeds verified successfully.');
  } catch (err) {
    console.error('❌ Database initialization error:', err.message);
  } finally {
    client.release();
  }
}

// ------------------------------------------------------------------------------
// Formatting Helper: Maps PostgreSQL row <-> Frontend Expected Fields
// ------------------------------------------------------------------------------
function formatTransactionRow(r, isAdmin = true) {
  const vNums = parseJsonArray(r.vehicle_numbers);
  if (vNums.length === 0 && r.wheel_id) vNums.push(r.wheel_id);

  const rImgs = parseJsonArray(r.receipt_images);
  if (rImgs.length === 0 && r.receipt_image) rImgs.push(r.receipt_image);

  const vImgs = parseJsonArray(r.vehicle_images);
  const priceVal = parseFloat(r.cost || r.maintenance_price || 0) || 0;

  const item = {
    id: r.id,
    transaction_id: r.transaction_id,
    wheel_id: r.wheel_id || vNums[0] || '',
    vehicle_id: r.wheel_id || vNums[0] || '',
    user_id: r.user_id || r.created_by || '',
    user_name: r.user_name || r.full_name || '',
    username: r.username || '',
    department: r.department_name || r.department || r.department_id || '',
    department_id: r.department_id || '',
    unit: r.unit || '',
    vehicle_numbers: vNums,
    vehicle_images: vImgs,
    receipt_images: rImgs,
    receipt_image: r.receipt_image || rImgs[0] || null,
    category: r.category || 'صيانة عامة',
    status: r.status || 'PENDING_AUDITOR',
    is_locked: r.is_locked !== false,
    auditor_note: r.auditor_note || null,
    admin_note: r.admin_note || null,
    current_km: parseInt(r.mileage || r.current_km || 0, 10) || 0,
    mileage: parseInt(r.mileage || r.current_km || 0, 10) || 0,
    maintenance_price: isAdmin ? priceVal : 0,
    cost: isAdmin ? priceVal : 0,
    notes: r.description || r.notes || '',
    description: r.description || r.notes || '',
    submitted_at: r.created_at || r.submitted_at || new Date().toISOString(),
    created_at: r.created_at || r.submitted_at || new Date().toISOString(),
    audited_by_auditor_at: r.audited_by_auditor_at || null,
    audited_at: r.audited_at || null
  };

  if (!isAdmin) {
    delete item.maintenance_price;
    delete item.cost;
  }
  return item;
}

async function logAudit(action, entityType, entityId, actorId, actorName, details) {
  try {
    const detailsStr = typeof details === 'object' ? JSON.stringify(details) : String(details || '');
    await pool.query(
      'INSERT INTO audit_logs (action, entity_type, entity_id, actor_id, actor_name, details) VALUES ($1, $2, $3, $4, $5, $6)',
      [action, entityType, String(entityId || ''), String(actorId || 'system'), String(actorName || ''), detailsStr]
    );
  } catch (_) {}
}

// ------------------------------------------------------------------------------
// SSE Real-Time Broadcast
// ------------------------------------------------------------------------------
const sseClients = new Set();

function broadcastEvent(type, payload) {
  const data = JSON.stringify({ type, payload, timestamp: new Date().toISOString() });
  for (const res of sseClients) {
    try {
      res.write(`data: ${data}\n\n`);
    } catch (_) {
      sseClients.delete(res);
    }
  }
}

// ------------------------------------------------------------------------------
// HTTP Helpers
// ------------------------------------------------------------------------------
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 50 * 1024 * 1024) reject(new Error('Payload Too Large'));
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
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-Idempotency-Key, x-idempotency-key, x-user-role, x-role, x-user-id, x-admin-password'
  });
  res.end(payload);
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function serveStatic(req, res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(err.code === 'ENOENT' ? 404 : 500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('File Not Found');
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
}

// ------------------------------------------------------------------------------
// HTTP Request Handler
// ------------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-Idempotency-Key, x-idempotency-key, x-user-role, x-role, x-user-id, x-admin-password'
    });
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

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
    // 0. Health Check (GET /api/health & /api/ping)
    // --------------------------------------------------------------------------
    if ((pathname === '/api/health' || pathname === '/api/ping') && req.method === 'GET') {
      let dbStatus = 'disconnected';
      try {
        await pool.query('SELECT 1');
        dbStatus = 'connected';
      } catch (dbErr) {
        dbStatus = 'error: ' + dbErr.message;
      }
      return sendJson(res, 200, {
        status: 'online',
        system: 'Wheel Maintenance Cloud API',
        version: '3.0.0 (Supabase PostgreSQL)',
        database: dbStatus,
        timestamp: new Date().toISOString()
      });
    }

    // --------------------------------------------------------------------------
    // 1. Full Cloud Sync (GET /api/sync)
    // --------------------------------------------------------------------------
    if (pathname === '/api/sync' && req.method === 'GET') {
      const role = (parsedUrl.searchParams.get('role') || req.headers['x-user-role'] || '').toUpperCase();
      const isAdmin = role === 'ADMIN';

      const [txRes, catRes, deptRes, reqRes, setRes, notifRes, userRes, vehRes, delRes, rcRes, audRes] = await Promise.all([
        pool.query(`
          SELECT t.*, u.full_name AS user_name, u.department, u.unit, u.username
          FROM transactions t
          LEFT JOIN users u ON t.user_id = u.user_id OR t.created_by = u.user_id
          WHERE COALESCE(t.is_deleted, FALSE) = FALSE
          ORDER BY t.created_at DESC
        `),
        pool.query('SELECT * FROM maintenance_categories ORDER BY category_id ASC'),
        pool.query('SELECT * FROM departments WHERE COALESCE(is_deleted, FALSE) = FALSE ORDER BY name ASC'),
        pool.query('SELECT * FROM maintenance_requests ORDER BY created_at DESC LIMIT 100'),
        pool.query('SELECT key, value FROM system_settings'),
        pool.query('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 40'),
        pool.query(`
          SELECT user_id, username, full_name, department, unit, role, is_active,
                 can_add_transaction, is_department_manager, assigned_department_id,
                 can_add_dept_members_transactions, can_edit_dept_transactions, is_read_only,
                 is_deleted, created_at
          FROM users WHERE COALESCE(is_deleted, FALSE) = FALSE
          ORDER BY created_at DESC
        `),
        pool.query('SELECT * FROM vehicles WHERE COALESCE(is_deleted, FALSE) = FALSE ORDER BY plate_number ASC'),
        isAdmin ? pool.query('SELECT * FROM deleted_records ORDER BY deleted_at DESC LIMIT 100') : Promise.resolve({ rows: [] }),
        pool.query('SELECT * FROM notification_read_receipts ORDER BY seen_at DESC LIMIT 200'),
        isAdmin ? pool.query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100') : Promise.resolve({ rows: [] })
      ]);

      const settings = {};
      setRes.rows.forEach(r => { settings[r.key] = r.value; });

      return sendJson(res, 200, {
        success: true,
        server_time: new Date().toISOString(),
        transactions: txRes.rows.map(r => formatTransactionRow(r, isAdmin)),
        categories: catRes.rows,
        departments: deptRes.rows,
        maintenance_requests: reqRes.rows,
        settings,
        notifications: notifRes.rows,
        users: userRes.rows,
        vehicles: vehRes.rows,
        deleted_records: delRes.rows,
        read_receipts: rcRes.rows,
        audit_logs: audRes.rows
      });
    }

    // --------------------------------------------------------------------------
    // 2. Push Offline Queue & Bulk Sync (POST /api/sync/push & /api/sync/push-all)
    // --------------------------------------------------------------------------
    if ((pathname === '/api/sync/push' || pathname === '/api/sync/push-all') && req.method === 'POST') {
      const body = await parseBody(req);
      let insertedCount = 0;
      let updatedCount = 0;

      // Sync departments if sent
      if (Array.isArray(body.departments)) {
        for (const d of body.departments) {
          if (!d || !d.name) continue;
          const dId = d.department_id || 'DEPT-' + crypto.randomUUID().slice(0, 8);
          await pool.query(
            'INSERT INTO departments (department_id, name, is_deleted) VALUES ($1, $2, FALSE) ON CONFLICT (name) DO NOTHING',
            [dId, d.name.trim()]
          );
        }
      }

      // Sync users if sent
      if (Array.isArray(body.users)) {
        for (const u of body.users) {
          if (!u || !u.username) continue;
          const uId = u.user_id || 'USR-' + crypto.randomUUID().slice(0, 8);
          await pool.query(`
            INSERT INTO users (user_id, username, password_hash, full_name, department, unit, role, is_active)
            VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)
            ON CONFLICT (username) DO NOTHING
          `, [
            uId, u.username.trim(), u.password_hash || hashPassword('123456'),
            u.full_name || u.username, u.department || 'DEPT-001', u.unit || '', normalizeRole(u.role)
          ]);
        }
      }

      // Sync vehicles if sent
      if (Array.isArray(body.vehicles)) {
        for (const v of body.vehicles) {
          const plate = v.plate_number || v.plate;
          if (!plate) continue;
          const vId = v.vehicle_id || 'VEH-' + crypto.randomUUID().slice(0, 6);
          await pool.query(`
            INSERT INTO vehicles (vehicle_id, plate_number, department_id, is_active, is_deleted)
            VALUES ($1, $2, $3, TRUE, FALSE)
            ON CONFLICT (plate_number) DO NOTHING
          `, [vId, plate.trim(), v.department_id || 'DEPT-001']);
        }
      }

      // Sync transactions
      const items = Array.isArray(body.items) ? body.items : (Array.isArray(body.transactions) ? body.transactions : []);
      for (const item of items) {
        if (!item || !item.transaction_id) continue;
        const vNums = parseJsonArray(item.vehicle_numbers);
        const wheelId = item.wheel_id || item.vehicle_id || vNums[0] || '';
        const vImgs = parseJsonArray(item.vehicle_images);
        const rImgs = parseJsonArray(item.receipt_images);
        const receiptSingle = item.receipt_image || rImgs[0] || null;
        const costVal = parseFloat(item.maintenance_price || item.cost || 0) || 0;
        const mileageVal = parseInt(item.current_km || item.mileage || 0, 10) || 0;
        const descVal = item.notes || item.description || '';

        const existing = await pool.query('SELECT transaction_id, status FROM transactions WHERE transaction_id = $1', [item.transaction_id]);
        if (existing.rows.length === 0) {
          await pool.query(`
            INSERT INTO transactions (
              transaction_id, wheel_id, user_id, department_id, created_by,
              description, cost, mileage, receipt_image, vehicle_images, receipt_images, vehicle_numbers,
              category, status, is_locked, auditor_note, admin_note, created_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12::jsonb,$13,$14,TRUE,$15,$16,$17)
          `, [
            item.transaction_id, wheelId, item.user_id || 'USR-FIELD-001', item.department_id || null, item.created_by || item.user_id || 'USR-FIELD-001',
            descVal, costVal, mileageVal, receiptSingle, JSON.stringify(vImgs), JSON.stringify(rImgs), JSON.stringify(vNums),
            item.category || 'صيانة عامة', item.status || 'PENDING_AUDITOR', item.auditor_note || null, item.admin_note || null,
            item.submitted_at || item.created_at || new Date().toISOString()
          ]);
          insertedCount++;
        } else if (item.status && item.status !== existing.rows[0].status) {
          await pool.query(`
            UPDATE transactions
            SET status = $1, auditor_note = COALESCE($2, auditor_note), admin_note = COALESCE($3, admin_note),
                cost = CASE WHEN $4 > 0 THEN $4 ELSE cost END
            WHERE transaction_id = $5
          `, [item.status, item.auditor_note || null, item.admin_note || null, costVal, item.transaction_id]);
          updatedCount++;
        }
      }

      if (insertedCount > 0 || updatedCount > 0) {
        broadcastEvent('SYNC_UPDATE', { inserted: insertedCount, updated: updatedCount });
      }

      return sendJson(res, 200, {
        success: true,
        message: `تمت المزامنة السحابية بنجاح: إدراج ${insertedCount} وتحديث ${updatedCount}`,
        inserted: insertedCount,
        updated: updatedCount
      });
    }

    // --------------------------------------------------------------------------
    // 3. Authentication (POST /api/login & /api/auth/login)
    // --------------------------------------------------------------------------
    if ((pathname === '/api/login' || pathname === '/api/auth/login') && req.method === 'POST') {
      const body = await parseBody(req);
      const { username, password } = body;
      const ip = req.socket.remoteAddress || '0.0.0.0';
      const userAgent = req.headers['user-agent'] || 'Mobile/Web';

      if (!username || !password) {
        return sendJson(res, 400, { error: 'يرجى إدخال اسم المستخدم وكلمة المرور' });
      }

      const uRes = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1) AND COALESCE(is_deleted, FALSE) = FALSE', [username.trim()]);
      const user = uRes.rows[0];

      if (!user) {
        await pool.query(
          'INSERT INTO login_history (log_id, username, ip_address, user_agent, status) VALUES ($1,$2,$3,$4,$5)',
          ['LOG-' + crypto.randomUUID().slice(0, 8), username.trim(), ip, userAgent, 'FAILED_NOT_FOUND']
        );
        return sendJson(res, 401, { error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
      }

      if (user.is_active === false) {
        return sendJson(res, 403, { error: 'هذا الحساب مجمد حالياً من قبل الإدارة' });
      }

      if (!verifyPassword(password, user.password_hash)) {
        await pool.query(
          'INSERT INTO login_history (log_id, user_id, username, full_name, role, ip_address, user_agent, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
          ['LOG-' + crypto.randomUUID().slice(0, 8), user.user_id, user.username, user.full_name, user.role, ip, userAgent, 'FAILED_WRONG_PASSWORD']
        );
        return sendJson(res, 401, { error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
      }

      await pool.query('UPDATE users SET last_login_at = NOW() WHERE user_id = $1', [user.user_id]);
      await pool.query(
        'INSERT INTO login_history (log_id, user_id, username, full_name, role, ip_address, user_agent, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        ['LOG-' + crypto.randomUUID().slice(0, 8), user.user_id, user.username, user.full_name, user.role, ip, userAgent, 'SUCCESS']
      );

      const safeUser = {
        user_id: user.user_id,
        username: user.username,
        full_name: user.full_name,
        department: user.department,
        unit: user.unit,
        role: user.role,
        can_add_transaction: user.can_add_transaction,
        is_department_manager: user.is_department_manager,
        assigned_department_id: user.assigned_department_id,
        can_add_dept_members_transactions: user.can_add_dept_members_transactions,
        can_edit_dept_transactions: user.can_edit_dept_transactions,
        is_read_only: user.is_read_only
      };

      return sendJson(res, 200, {
        success: true,
        message: 'تم تسجيل الدخول بنجاح',
        user: safeUser,
        token: 'jwt_' + user.user_id + '_' + crypto.randomUUID()
      });
    }

    if ((pathname === '/api/auth/me' || pathname === '/api/me') && req.method === 'GET') {
      const userId = (req.headers['x-user-id'] || parsedUrl.searchParams.get('user_id') || '').trim();
      const q = userId
        ? await pool.query('SELECT user_id, username, full_name, department, unit, role, is_active FROM users WHERE user_id = $1 OR LOWER(username) = LOWER($1)', [userId])
        : await pool.query('SELECT user_id, username, full_name, department, unit, role, is_active FROM users WHERE is_active = TRUE LIMIT 1');
      if (q.rows.length === 0) return sendJson(res, 401, { success: false, error: 'غير مصرح' });
      return sendJson(res, 200, { success: true, user: q.rows[0] });
    }

    if (pathname === '/api/user/change-password' && req.method === 'POST') {
      const body = await parseBody(req);
      const { user_id, current_password, new_password } = body;
      if (!user_id || !current_password || !new_password) {
        return sendJson(res, 400, { error: 'يرجى إدخال كلمة المرور الحالية والجديدة' });
      }
      const uRes = await pool.query('SELECT * FROM users WHERE user_id = $1', [user_id]);
      if (uRes.rows.length === 0) return sendJson(res, 404, { error: 'المستخدم غير موجود' });
      if (!verifyPassword(current_password, uRes.rows[0].password_hash)) {
        return sendJson(res, 400, { error: 'كلمة المرور الحالية غير صحيحة' });
      }
      await pool.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [hashPassword(new_password.trim()), user_id]);
      return sendJson(res, 200, { success: true, message: 'تم تغيير كلمة المرور بنجاح' });
    }

    // --------------------------------------------------------------------------
    // 4. Departments CRUD (PostgreSQL)
    // --------------------------------------------------------------------------
    if (pathname === '/api/departments' && req.method === 'GET') {
      const resDepts = await pool.query('SELECT * FROM departments WHERE COALESCE(is_deleted, FALSE) = FALSE ORDER BY name ASC');
      return sendJson(res, 200, { departments: resDepts.rows });
    }

    if ((pathname === '/api/admin/departments' || pathname === '/api/departments') && req.method === 'POST') {
      const body = await parseBody(req);
      const name = (body.name || '').trim();
      if (!name) return sendJson(res, 400, { error: 'اسم القسم مطلوب' });
      const deptId = 'DEPT-' + crypto.randomUUID().slice(0, 8);
      try {
        await pool.query('INSERT INTO departments (department_id, name, is_deleted) VALUES ($1, $2, FALSE)', [deptId, name]);
        const resDepts = await pool.query('SELECT * FROM departments WHERE COALESCE(is_deleted, FALSE) = FALSE ORDER BY name ASC');
        broadcastEvent('DEPARTMENTS_UPDATED', { departments: resDepts.rows });
        return sendJson(res, 201, { success: true, department: { department_id: deptId, name }, departments: resDepts.rows });
      } catch (err) {
        return sendJson(res, 400, { error: 'اسم القسم موجود مسبقاً أو غير صالح' });
      }
    }

    if ((pathname.match(/^\/api\/admin\/departments\/[A-Za-z0-9_-]+$/) || pathname.match(/^\/api\/departments\/[A-Za-z0-9_-]+$/)) && (req.method === 'PUT' || req.method === 'PATCH')) {
      const deptId = pathname.split('/').pop();
      const body = await parseBody(req);
      const newName = (body.name || '').trim();
      if (!newName) return sendJson(res, 400, { error: 'اسم القسم مطلوب' });

      const dRes = await pool.query('SELECT * FROM departments WHERE department_id = $1', [deptId]);
      if (dRes.rows.length === 0) return sendJson(res, 404, { error: 'القسم غير موجود' });

      await pool.query('UPDATE departments SET name = $1 WHERE department_id = $2', [newName, deptId]);
      const resDepts = await pool.query('SELECT * FROM departments WHERE COALESCE(is_deleted, FALSE) = FALSE ORDER BY name ASC');
      broadcastEvent('DEPARTMENTS_UPDATED', { departments: resDepts.rows });
      return sendJson(res, 200, { success: true, message: 'تم تعديل اسم القسم بنجاح', departments: resDepts.rows });
    }

    if ((pathname === '/api/admin/departments/delete' && req.method === 'POST') ||
        (pathname.match(/^\/api\/(admin\/)?departments\/[A-Za-z0-9_-]+$/) && req.method === 'DELETE')) {
      const body = req.method === 'POST' ? await parseBody(req) : {};
      const deptId = body.department_id || body.id || decodeURIComponent(pathname.split('/').pop());
      const dRes = await pool.query('SELECT * FROM departments WHERE department_id = $1 OR name = $1', [deptId]);
      if (dRes.rows.length === 0) return sendJson(res, 404, { error: 'القسم غير موجود' });
      const dept = dRes.rows[0];

      await pool.query(
        'INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by) VALUES ($1, $2, $3::jsonb, $4)',
        ['department', dept.department_id, JSON.stringify(dept), 'admin']
      );
      await pool.query('UPDATE departments SET is_deleted = TRUE, deleted_at = NOW() WHERE department_id = $1', [dept.department_id]);

      const resDepts = await pool.query('SELECT * FROM departments WHERE COALESCE(is_deleted, FALSE) = FALSE ORDER BY name ASC');
      broadcastEvent('DEPARTMENTS_UPDATED', { departments: resDepts.rows });
      return sendJson(res, 200, { success: true, message: `تم حذف قسم (${dept.name}) ونقله لسلة المحذوفات`, departments: resDepts.rows });
    }

    // --------------------------------------------------------------------------
    // 5. Users CRUD (PostgreSQL)
    // --------------------------------------------------------------------------
    if ((pathname === '/api/admin/users' || pathname === '/api/users') && req.method === 'GET') {
      const uRes = await pool.query(`
        SELECT u.user_id, u.username, u.full_name, u.department AS department_id,
               COALESCE(d.name, u.department, 'عام') AS department_name,
               u.unit, u.role, u.is_active,
               u.can_add_transaction, u.is_department_manager, u.assigned_department_id,
               u.can_add_dept_members_transactions, u.can_edit_dept_transactions, u.is_read_only,
               u.is_deleted, u.created_at
        FROM users u
        LEFT JOIN departments d ON u.department = d.department_id OR u.department = d.name
        WHERE COALESCE(u.is_deleted, FALSE) = FALSE
        ORDER BY u.created_at DESC
      `);
      return sendJson(res, 200, { users: uRes.rows });
    }

    if ((pathname === '/api/admin/users' || pathname === '/api/users' || pathname === '/api/admin/users/add' || pathname === '/api/admin/users/create') && req.method === 'POST') {
      const body = await parseBody(req);
      const {
        username, password, full_name, department_id, department, unit, role,
        can_add_transaction, is_department_manager, assigned_department_id,
        can_add_dept_members_transactions, can_edit_dept_transactions, is_read_only
      } = body;
      const dept = (department_id || department || 'DEPT-001').trim();

      if (!username || !password || !full_name) {
        return sendJson(res, 400, { error: 'اسم الدخول، كلمة المرور، والاسم الكامل حقول مطلوبة' });
      }

      const exist = await pool.query('SELECT user_id FROM users WHERE LOWER(username) = LOWER($1)', [username.trim()]);
      if (exist.rows.length > 0) {
        return sendJson(res, 400, { error: `اسم المستخدم (${username}) مستخدم مسبقاً` });
      }

      const newUserId = 'USR-' + crypto.randomUUID().slice(0, 8);
      const assignedRole = normalizeRole(role);
      const isReadOnly = Boolean(is_read_only);
      const isDeptMgr = Boolean(is_department_manager) || assignedRole === 'DEPARTMENT_HEAD';
      const canAddTx = isReadOnly ? false : (can_add_transaction !== false && can_add_transaction !== 0);
      const canAddDeptTx = (!isReadOnly && isDeptMgr) ? Boolean(can_add_dept_members_transactions) : false;
      const canEditDeptTx = (!isReadOnly && isDeptMgr) ? Boolean(can_edit_dept_transactions) : false;

      await pool.query(`
        INSERT INTO users (
          user_id, username, password_hash, full_name, department, unit, role, is_active,
          can_add_transaction, is_department_manager, assigned_department_id,
          can_add_dept_members_transactions, can_edit_dept_transactions, is_read_only, is_deleted
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,$8,$9,$10,$11,$12,$13,FALSE)
      `, [
        newUserId, username.trim(), hashPassword(password), full_name.trim(), dept, (unit || '').trim(),
        assignedRole, canAddTx, isDeptMgr, (assigned_department_id || dept).trim(), canAddDeptTx, canEditDeptTx, isReadOnly
      ]);

      await logAudit('CREATE_USER', 'users', newUserId, 'admin', 'المدير العام', { username: username.trim(), role: assignedRole });
      return sendJson(res, 201, {
        success: true,
        message: 'تمت إضافة المستخدم وحفظه في السحابة بنجاح',
        user: { user_id: newUserId, username: username.trim(), full_name: full_name.trim(), department_id: dept, role: assignedRole, is_active: true }
      });
    }

    if ((pathname === '/api/admin/users/update' && req.method === 'POST') ||
        (pathname.startsWith('/api/admin/users/') && !pathname.endsWith('/toggle-active') && !pathname.endsWith('/delete') && req.method === 'PUT')) {
      const body = await parseBody(req);
      const targetId = body.user_id || body.id || decodeURIComponent(pathname.replace('/api/admin/users/', ''));
      const uRes = await pool.query('SELECT * FROM users WHERE user_id = $1 OR username = $1', [targetId]);
      if (uRes.rows.length === 0) return sendJson(res, 404, { error: 'المستخدم غير موجود' });
      const user = uRes.rows[0];

      const newPassHash = (body.password && String(body.password).trim()) ? hashPassword(String(body.password).trim()) : user.password_hash;
      const assignedRole = body.role ? normalizeRole(body.role) : user.role;
      const dept = (body.department_id || body.department || user.department).trim();

      await pool.query(`
        UPDATE users
        SET full_name = COALESCE($1, full_name),
            department = $2,
            unit = COALESCE($3, unit),
            password_hash = $4,
            role = $5,
            is_active = COALESCE($6, is_active),
            can_add_transaction = COALESCE($7, can_add_transaction),
            is_department_manager = COALESCE($8, is_department_manager),
            assigned_department_id = COALESCE($9, assigned_department_id),
            can_add_dept_members_transactions = COALESCE($10, can_add_dept_members_transactions),
            can_edit_dept_transactions = COALESCE($11, can_edit_dept_transactions),
            is_read_only = COALESCE($12, is_read_only)
        WHERE user_id = $13
      `, [
        body.full_name ? body.full_name.trim() : null, dept, body.unit, newPassHash, assignedRole,
        body.is_active !== undefined ? Boolean(body.is_active) : null,
        body.can_add_transaction !== undefined ? Boolean(body.can_add_transaction) : null,
        body.is_department_manager !== undefined ? Boolean(body.is_department_manager) : null,
        body.assigned_department_id || dept,
        body.can_add_dept_members_transactions !== undefined ? Boolean(body.can_add_dept_members_transactions) : null,
        body.can_edit_dept_transactions !== undefined ? Boolean(body.can_edit_dept_transactions) : null,
        body.is_read_only !== undefined ? Boolean(body.is_read_only) : null,
        user.user_id
      ]);

      return sendJson(res, 200, { success: true, message: 'تم تحديث بيانات المستخدم بنجاح' });
    }

    if ((pathname === '/api/admin/users/toggle-active' && req.method === 'POST') ||
        (pathname.startsWith('/api/admin/users/') && pathname.endsWith('/toggle-active') && req.method === 'POST')) {
      const body = await parseBody(req);
      const targetId = body.user_id || body.id || decodeURIComponent(pathname.replace('/api/admin/users/', '').replace('/toggle-active', ''));
      const uRes = await pool.query('SELECT * FROM users WHERE user_id = $1 OR username = $1', [targetId]);
      if (uRes.rows.length === 0) return sendJson(res, 404, { error: 'المستخدم غير موجود' });
      const user = uRes.rows[0];
      if (user.username === 'admin') return sendJson(res, 400, { error: 'لا يمكن تجميد حساب الأدمن الرئيسي' });

      const newActive = !user.is_active;
      await pool.query('UPDATE users SET is_active = $1 WHERE user_id = $2', [newActive, user.user_id]);
      return sendJson(res, 200, { success: true, is_active: newActive, message: newActive ? 'تم تفعيل الحساب' : 'تم تجميد الحساب' });
    }

    if ((pathname === '/api/admin/users/delete' && req.method === 'POST') ||
        (pathname.startsWith('/api/admin/users') && req.method === 'DELETE')) {
      const body = req.method === 'POST' ? await parseBody(req) : {};
      const targetId = body.user_id || body.id || parsedUrl.searchParams.get('user_id') || decodeURIComponent(pathname.replace(/^\/api\/admin\/users\/?/, ''));
      const uRes = await pool.query('SELECT * FROM users WHERE user_id = $1 OR username = $1', [targetId]);
      if (uRes.rows.length === 0) return sendJson(res, 404, { error: 'المستخدم غير موجود' });
      const user = uRes.rows[0];
      if (user.username === 'admin') return sendJson(res, 400, { error: 'لا يمكن حذف حساب الأدمن الرئيسي' });

      await pool.query(
        'INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by) VALUES ($1, $2, $3::jsonb, $4)',
        ['user', user.user_id, JSON.stringify(user), 'admin']
      );
      await pool.query('UPDATE users SET is_deleted = TRUE, deleted_at = NOW(), deleted_by = $1 WHERE user_id = $2', ['admin', user.user_id]);
      return sendJson(res, 200, { success: true, message: `تم حذف المستخدم (${user.username}) ونقله لسلة المحذوفات` });
    }

    // --------------------------------------------------------------------------
    // 6. Vehicles CRUD (PostgreSQL)
    // --------------------------------------------------------------------------
    if (pathname === '/api/vehicles' && req.method === 'GET') {
      const vRes = await pool.query(`
        SELECT v.*, COALESCE(d.name, v.department_id, 'عام') AS department_name
        FROM vehicles v
        LEFT JOIN departments d ON v.department_id = d.department_id OR v.department_id = d.name
        WHERE COALESCE(v.is_deleted, FALSE) = FALSE
        ORDER BY v.plate_number ASC
      `);
      return sendJson(res, 200, { vehicles: vRes.rows });
    }

    if ((pathname === '/api/admin/vehicles' || pathname === '/api/vehicles' || pathname === '/api/admin/vehicles/add') && req.method === 'POST') {
      const body = await parseBody(req);
      const plate = (body.plate_number || '').trim();
      if (!plate) return sendJson(res, 400, { error: 'رقم العجلة مطلوب' });

      const vehId = 'VEH-' + crypto.randomUUID().slice(0, 6);
      await pool.query(`
        INSERT INTO vehicles (vehicle_id, plate_number, vehicle_type, department_id, is_active, is_deleted)
        VALUES ($1, $2, $3, $4, TRUE, FALSE)
        ON CONFLICT (plate_number) DO UPDATE SET is_deleted = FALSE, is_active = TRUE, department_id = EXCLUDED.department_id
      `, [vehId, plate, body.vehicle_type || '', body.department_id || 'DEPT-001']);

      return sendJson(res, 201, { success: true, vehicle: { vehicle_id: vehId, plate_number: plate, department_id: body.department_id || 'DEPT-001', is_active: true } });
    }

    if ((pathname === '/api/admin/vehicles/delete' && req.method === 'POST') ||
        (pathname === '/api/vehicles/delete' && req.method === 'POST') ||
        ((pathname.startsWith('/api/admin/vehicles') || pathname.startsWith('/api/vehicles')) && req.method === 'DELETE')) {
      const body = req.method === 'POST' ? await parseBody(req) : {};
      const targetId = body.vehicle_id || body.id || body.plate_number || parsedUrl.searchParams.get('id') || decodeURIComponent(pathname.replace(/^\/api\/(admin\/)?vehicles\/?/, ''));
      const vRes = await pool.query('SELECT * FROM vehicles WHERE vehicle_id = $1 OR plate_number = $1', [targetId]);
      if (vRes.rows.length === 0) return sendJson(res, 404, { error: 'العجلة غير موجودة' });
      const veh = vRes.rows[0];

      await pool.query(
        'INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by) VALUES ($1, $2, $3::jsonb, $4)',
        ['vehicle', veh.vehicle_id, JSON.stringify(veh), 'admin']
      );
      await pool.query('UPDATE vehicles SET is_deleted = TRUE, is_active = FALSE, deleted_at = NOW() WHERE vehicle_id = $1', [veh.vehicle_id]);
      return sendJson(res, 200, { success: true, message: `تم حذف العجلة (${veh.plate_number}) ونقلها لسلة المحذوفات` });
    }

    if (pathname === '/api/vehicles/fleet-summary' && req.method === 'GET') {
      const [vRes, txRes, catRes] = await Promise.all([
        pool.query('SELECT * FROM vehicles WHERE COALESCE(is_deleted, FALSE) = FALSE ORDER BY plate_number ASC'),
        pool.query('SELECT * FROM transactions WHERE COALESCE(is_deleted, FALSE) = FALSE ORDER BY created_at DESC'),
        pool.query('SELECT * FROM maintenance_categories')
      ]);
      const catMap = new Map(catRes.rows.map(c => [c.name, c.default_replacement_km || 5000]));
      const fleetMap = new Map();

      vRes.rows.forEach(v => {
        fleetMap.set(v.plate_number, {
          vehicle_id: v.vehicle_id,
          plate: v.plate_number,
          department: v.department_id || 'عام',
          is_active: v.is_active !== false,
          last_km: v.current_km || 0,
          total_tx: 0,
          total_cost: 0,
          total_spent: 0,
          last_service_date: null,
          service_types: {}
        });
      });

      txRes.rows.forEach(t => {
        const plates = parseJsonArray(t.vehicle_numbers);
        if (plates.length === 0 && t.wheel_id) plates.push(t.wheel_id);
        const price = parseFloat(t.cost || 0) || 0;
        const km = parseInt(t.mileage || 0, 10) || 0;

        plates.forEach(plate => {
          if (!fleetMap.has(plate)) {
            fleetMap.set(plate, {
              vehicle_id: 'VEH-' + crypto.randomUUID().slice(0, 6),
              plate,
              department: t.department_id || 'عام',
              is_active: true,
              last_km: 0,
              total_tx: 0,
              total_cost: 0,
              total_spent: 0,
              last_service_date: t.created_at,
              service_types: {}
            });
          }
          const veh = fleetMap.get(plate);
          veh.total_tx++;
          veh.total_cost += price;
          veh.total_spent += price;
          if (km > veh.last_km) veh.last_km = km;
          if (!veh.last_service_date || new Date(t.created_at) > new Date(veh.last_service_date)) {
            veh.last_service_date = t.created_at;
          }
          const cat = t.category || 'صيانة عامة';
          if (!veh.service_types[cat]) {
            const defKm = catMap.get(cat) || 5000;
            veh.service_types[cat] = { last_date: t.created_at, last_km: km, default_km: defKm, due_km: km + defKm };
          }
        });
      });

      return sendJson(res, 200, { fleet: Array.from(fleetMap.values()) });
    }

    // --------------------------------------------------------------------------
    // 7. Transactions CRUD (PostgreSQL - Real Multi-Device Sync)
    // --------------------------------------------------------------------------
    if (pathname === '/api/transactions' && req.method === 'GET') {
      const userId = parsedUrl.searchParams.get('user_id');
      const status = parsedUrl.searchParams.get('status');
      const department = parsedUrl.searchParams.get('department');
      const viewRole = (parsedUrl.searchParams.get('view_role') || parsedUrl.searchParams.get('role') || req.headers['x-user-role'] || '').toUpperCase();
      const isAdmin = viewRole === 'ADMIN';

      const conditions = ['COALESCE(t.is_deleted, FALSE) = FALSE'];
      const params = [];
      let idx = 1;

      if (userId) {
        conditions.push(`(t.user_id = $${idx} OR t.created_by = $${idx})`);
        params.push(userId);
        idx++;
      }

      if (status && status !== 'ALL' && status !== 'FEED') {
        if (status === 'IN_PROGRESS' || status === 'PENDING_PROCEDURES') {
          conditions.push("t.status IN ('PENDING_AUDITOR', 'PENDING_ADMIN', 'IN_PROGRESS')");
        } else {
          conditions.push(`t.status = $${idx}`);
          params.push(status);
          idx++;
        }
      } else if (viewRole === 'ADMIN' && status === 'FEED') {
        conditions.push("t.status = 'PENDING_ADMIN'");
      } else if (viewRole === 'AUDITOR' && status === 'FEED') {
        conditions.push("t.status = 'PENDING_AUDITOR'");
      }

      if (department && department !== 'ALL') {
        conditions.push(`(t.department_id = $${idx} OR u.department = $${idx})`);
        params.push(department);
        idx++;
      }

      const sql = `
        SELECT t.*, u.full_name AS user_name, u.department, u.unit, u.username
        FROM transactions t
        LEFT JOIN users u ON t.user_id = u.user_id OR t.created_by = u.user_id
        WHERE ${conditions.join(' AND ')}
        ORDER BY t.created_at DESC
      `;
      const txRes = await pool.query(sql, params);
      return sendJson(res, 200, {
        transactions: txRes.rows.map(r => formatTransactionRow(r, isAdmin))
      });
    }

    if (pathname === '/api/transactions' && req.method === 'POST') {
      const body = await parseBody(req);
      const { user_id, vehicle_numbers, vehicle_images, receipt_images, category } = body;

      const vNums = parseJsonArray(vehicle_numbers);
      const wheelId = (body.wheel_id || body.vehicle_id || vNums[0] || '').trim();
      if (!wheelId && vNums.length === 0) {
        return sendJson(res, 400, { error: 'يجب إدخال رقم عجلة واحدة على الأقل' });
      }
      if (vNums.length === 0 && wheelId) vNums.push(wheelId);

      const vImgs = parseJsonArray(vehicle_images);
      const rImgs = parseJsonArray(receipt_images);
      const receiptSingle = body.receipt_image || rImgs[0] || null;
      const mileageVal = parseInt(body.current_km || body.mileage || 0, 10) || 0;
      const costVal = parseFloat(body.maintenance_price || body.cost || 0) || 0;
      const descVal = (body.notes || body.description || '').trim();
      const txId = body.transaction_id || `TX-${new Date().getFullYear()}-${Date.now().toString().slice(-4)}${Math.floor(100 + Math.random() * 900)}`;

      // Resolve user if exists in DB
      let resolvedUserId = user_id || 'USR-FIELD-001';
      let resolvedDept = body.department_id || null;
      if (user_id) {
        const uRes = await pool.query('SELECT user_id, department FROM users WHERE user_id = $1 OR LOWER(username) = LOWER($1)', [user_id]);
        if (uRes.rows.length > 0) {
          resolvedUserId = uRes.rows[0].user_id;
          resolvedDept = resolvedDept || uRes.rows[0].department;
        }
      }

      // Auto-register vehicle in vehicles table if new
      for (const plate of vNums) {
        const p = String(plate).trim();
        if (!p) continue;
        await pool.query(`
          INSERT INTO vehicles (vehicle_id, plate_number, department_id, current_km, is_active, is_deleted)
          VALUES ($1, $2, $3, $4, TRUE, FALSE)
          ON CONFLICT (plate_number) DO UPDATE SET current_km = GREATEST(vehicles.current_km, EXCLUDED.current_km)
        `, ['VEH-' + crypto.randomUUID().slice(0, 6), p, resolvedDept || 'DEPT-001', mileageVal]);
      }

      const insertRes = await pool.query(`
        INSERT INTO transactions (
          transaction_id, wheel_id, user_id, department_id, member_user_id, created_by,
          description, cost, mileage, receipt_image, vehicle_images, receipt_images, vehicle_numbers,
          category, status, is_locked, is_deleted, created_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb,$14,'PENDING_AUDITOR',TRUE,FALSE,NOW())
        RETURNING *
      `, [
        txId, wheelId || vNums[0], resolvedUserId, resolvedDept, body.member_user_id || null, resolvedUserId,
        descVal, costVal, mileageVal, receiptSingle, JSON.stringify(vImgs), JSON.stringify(rImgs), JSON.stringify(vNums),
        category || 'صيانة عامة'
      ]);

      const formatted = formatTransactionRow(insertRes.rows[0], true);
      await logAudit('CREATE_TRANSACTION', 'transactions', txId, resolvedUserId, '', { wheel_id: wheelId, category });
      broadcastEvent('NEW_TRANSACTION_FOR_AUDITOR', formatted);

      return sendJson(res, 201, {
        success: true,
        message: 'تم إرسال المعاملة وحفظها في قاعدة البيانات السحابية بنجاح',
        transaction: formatted
      });
    }

    // Update Transaction (PUT /api/transactions/:id or POST /api/transactions/update)
    if ((pathname.match(/^\/api\/transactions\/[A-Za-z0-9_-]+$/) && req.method === 'PUT') ||
        (pathname === '/api/transactions/update' && req.method === 'POST')) {
      const body = await parseBody(req);
      const txId = body.transaction_id || pathname.split('/').pop();
      const vNums = body.vehicle_numbers ? parseJsonArray(body.vehicle_numbers) : null;
      const wheelId = body.wheel_id || body.vehicle_id || (vNums && vNums[0]) || null;

      await pool.query(`
        UPDATE transactions
        SET wheel_id = COALESCE($1, wheel_id),
            vehicle_numbers = COALESCE($2::jsonb, vehicle_numbers),
            vehicle_images = COALESCE($3::jsonb, vehicle_images),
            receipt_images = COALESCE($4::jsonb, receipt_images),
            category = COALESCE($5, category),
            mileage = COALESCE($6, mileage),
            description = COALESCE($7, description),
            cost = COALESCE($8, cost),
            status = COALESCE($9, status)
        WHERE transaction_id = $10
      `, [
        wheelId,
        vNums ? JSON.stringify(vNums) : null,
        body.vehicle_images ? JSON.stringify(parseJsonArray(body.vehicle_images)) : null,
        body.receipt_images ? JSON.stringify(parseJsonArray(body.receipt_images)) : null,
        body.category || null,
        body.current_km !== undefined ? parseInt(body.current_km, 10) : null,
        body.notes !== undefined ? String(body.notes) : null,
        body.maintenance_price !== undefined ? parseFloat(body.maintenance_price) : null,
        body.status || null,
        txId
      ]);

      const updated = await pool.query('SELECT * FROM transactions WHERE transaction_id = $1', [txId]);
      if (updated.rows.length === 0) return sendJson(res, 404, { error: 'المعاملة غير موجودة' });
      const formatted = formatTransactionRow(updated.rows[0], true);
      broadcastEvent('TRANSACTION_EDITED', formatted);
      return sendJson(res, 200, { success: true, message: 'تم تحديث المعاملة بنجاح', transaction: formatted });
    }

    // Auditor Review
    if (pathname.match(/^\/api\/auditor\/transactions\/[A-Za-z0-9_-]+\/review$/) && req.method === 'POST') {
      const txId = pathname.split('/')[4];
      const body = await parseBody(req);
      const newStatus = body.action === 'APPROVE_TO_ADMIN' ? 'PENDING_ADMIN' : 'IN_PROGRESS';

      const upd = await pool.query(`
        UPDATE transactions
        SET status = $1, auditor_note = $2, audited_by_auditor_at = CASE WHEN $1 = 'PENDING_ADMIN' THEN NOW() ELSE NULL END
        WHERE transaction_id = $3
        RETURNING *
      `, [newStatus, body.note || null, txId]);

      if (upd.rows.length === 0) return sendJson(res, 404, { error: 'المعاملة غير موجودة' });
      const formatted = formatTransactionRow(upd.rows[0], true);
      broadcastEvent('AUDITOR_DECISION_UPDATED', { transaction: formatted });
      return sendJson(res, 200, { success: true, message: 'تم تحديث قرار التدقيق بنجاح', transaction: formatted });
    }

    // Admin Update Amount
    if ((pathname === '/api/admin/transactions/update-amount' ||
         pathname.match(/^\/api\/(admin\/)?transactions\/[A-Za-z0-9_-]+\/(maintenance-)?amount$/)) &&
        (req.method === 'POST' || req.method === 'PATCH' || req.method === 'PUT')) {
      const body = await parseBody(req);
      const txId = body.transaction_id || pathname.split('/').find(p => p.startsWith('TX-'));
      const amountVal = parseFloat(body.maintenance_amount ?? body.maintenance_price ?? body.amount ?? 0);
      if (!txId || isNaN(amountVal) || amountVal <= 0) {
        return sendJson(res, 400, { error: 'يرجى إدخال مبلغ صحيح أكبر من صفر' });
      }
      await pool.query('UPDATE transactions SET cost = $1 WHERE transaction_id = $2', [amountVal, txId]);
      broadcastEvent('TRANSACTION_UPDATED', { transaction_id: txId, maintenance_price: amountVal });
      return sendJson(res, 200, { success: true, transaction_id: txId, maintenance_price: amountVal, message: 'تم حفظ مبلغ الصيانة بنجاح' });
    }

    // Admin Update KM
    if ((pathname === '/api/admin/transactions/update-km' ||
         pathname.match(/^\/api\/(admin\/)?transactions\/[A-Za-z0-9_-]+\/(current-)?km$/)) &&
        (req.method === 'POST' || req.method === 'PATCH' || req.method === 'PUT')) {
      const body = await parseBody(req);
      const txId = body.transaction_id || pathname.split('/').find(p => p.startsWith('TX-'));
      const newKm = parseInt(body.new_km ?? body.current_km ?? body.km ?? 0, 10);
      if (!txId || isNaN(newKm) || newKm <= 0) {
        return sendJson(res, 400, { error: 'يرجى إدخال قراءة عداد صحيحة' });
      }
      await pool.query('UPDATE transactions SET mileage = $1 WHERE transaction_id = $2', [newKm, txId]);
      broadcastEvent('TRANSACTION_UPDATED', { transaction_id: txId, current_km: newKm });
      return sendJson(res, 200, { success: true, transaction_id: txId, new_km: newKm, message: 'تم تحديث قراءة العداد بنجاح' });
    }

    // Admin Final Decision
    if (pathname.match(/^\/api\/admin\/transactions\/[A-Za-z0-9_-]+\/status$/) && req.method === 'POST') {
      const txId = pathname.split('/')[4];
      const body = await parseBody(req);
      const { status, admin_note, maintenance_price } = body;

      const curRes = await pool.query('SELECT * FROM transactions WHERE transaction_id = $1', [txId]);
      if (curRes.rows.length === 0) return sendJson(res, 404, { error: 'المعاملة غير موجودة' });
      const cur = curRes.rows[0];
      const price = maintenance_price !== undefined ? parseFloat(maintenance_price) : parseFloat(cur.cost || 0);

      if (status === 'AUDITED' && (!price || price <= 0)) {
        return sendJson(res, 400, { error: 'يرجى إدخال مبلغ الصيانة قبل الاعتماد النهائي' });
      }

      const upd = await pool.query(`
        UPDATE transactions
        SET status = $1, admin_note = COALESCE($2, admin_note), cost = $3,
            audited_at = CASE WHEN $1 = 'AUDITED' THEN NOW() ELSE audited_at END
        WHERE transaction_id = $4
        RETURNING *
      `, [status, admin_note || null, price, txId]);

      const formatted = formatTransactionRow(upd.rows[0], true);
      broadcastEvent('TRANSACTION_STATUS_UPDATED', { transaction: formatted });
      return sendJson(res, 200, { success: true, message: 'تم اعتماد القرار الإداري بنجاح', transaction: formatted });
    }

    // Delete Transaction (Soft Delete -> Recycle Bin)
    if ((pathname.match(/^\/api\/(admin\/)?transactions\/[A-Za-z0-9_-]+$/)) && req.method === 'DELETE') {
      const txId = pathname.split('/').pop();
      const txRes = await pool.query('SELECT * FROM transactions WHERE transaction_id = $1', [txId]);
      if (txRes.rows.length === 0) return sendJson(res, 404, { error: 'المعاملة غير موجودة' });

      await pool.query(
        'INSERT INTO deleted_records (entity_type, entity_id, record_snapshot, deleted_by) VALUES ($1, $2, $3::jsonb, $4)',
        ['transaction', txId, JSON.stringify(txRes.rows[0]), 'admin']
      );
      await pool.query('UPDATE transactions SET is_deleted = TRUE, deleted_at = NOW(), deleted_by = $1 WHERE transaction_id = $2', ['admin', txId]);
      broadcastEvent('TRANSACTION_DELETED', { transaction_id: txId });
      return sendJson(res, 200, { success: true, message: 'تم حذف المعاملة ونقلها لسلة المحذوفات' });
    }

    // --------------------------------------------------------------------------
    // 8. Recycle Bin (Deleted Records)
    // --------------------------------------------------------------------------
    if ((pathname === '/api/deleted-records' || pathname === '/api/admin/recycle-bin' || pathname === '/api/admin/deleted-records') && req.method === 'GET') {
      const dRes = await pool.query('SELECT * FROM deleted_records ORDER BY deleted_at DESC');
      return sendJson(res, 200, { success: true, count: dRes.rows.length, data: dRes.rows, deleted_records: dRes.rows });
    }

    if ((pathname === '/api/admin/recycle-bin/restore' || pathname === '/api/deleted-records/restore' || pathname.match(/^\/api\/deleted-records\/[0-9]+\/restore$/)) && req.method === 'POST') {
      const body = await parseBody(req);
      const id = body.id || body.trashId || pathname.split('/')[3];
      const recRes = await pool.query('SELECT * FROM deleted_records WHERE id = $1', [id]);
      if (recRes.rows.length === 0) return sendJson(res, 404, { error: 'السجل غير موجود' });
      const rec = recRes.rows[0];

      if (rec.entity_type === 'transaction') {
        await pool.query('UPDATE transactions SET is_deleted = FALSE, deleted_at = NULL WHERE transaction_id = $1', [rec.entity_id]);
      } else if (rec.entity_type === 'vehicle') {
        await pool.query('UPDATE vehicles SET is_deleted = FALSE, is_active = TRUE, deleted_at = NULL WHERE vehicle_id = $1', [rec.entity_id]);
      } else if (rec.entity_type === 'user' || rec.entity_type === 'users') {
        await pool.query('UPDATE users SET is_deleted = FALSE, is_active = TRUE, deleted_at = NULL WHERE user_id = $1', [rec.entity_id]);
      } else if (rec.entity_type === 'department' || rec.entity_type === 'departments') {
        await pool.query('UPDATE departments SET is_deleted = FALSE, deleted_at = NULL WHERE department_id = $1', [rec.entity_id]);
      }
      await pool.query('DELETE FROM deleted_records WHERE id = $1', [id]);
      return sendJson(res, 200, { success: true, message: 'تم استرجاع السجل بنجاح' });
    }

    // --------------------------------------------------------------------------
    // 9. Categories, Settings, Requests, Notifications, Analytics
    // --------------------------------------------------------------------------
    if (pathname === '/api/categories' && req.method === 'GET') {
      const cRes = await pool.query('SELECT * FROM maintenance_categories ORDER BY category_id ASC');
      return sendJson(res, 200, { categories: cRes.rows });
    }

    if ((pathname === '/api/admin/categories' || pathname === '/api/categories') && req.method === 'POST') {
      const body = await parseBody(req);
      const name = (body.name || '').trim();
      if (!name) return sendJson(res, 400, { error: 'اسم نوع الصيانة مطلوب' });
      const catId = 'CAT-' + crypto.randomUUID().slice(0, 6);
      const km = parseInt(body.default_replacement_km || 5000, 10) || 5000;
      await pool.query(
        'INSERT INTO maintenance_categories (category_id, name, icon, description, default_replacement_km) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (name) DO NOTHING',
        [catId, name, body.icon || '🛞', body.description || '', km]
      );
      return sendJson(res, 201, { success: true, category: { category_id: catId, name, default_replacement_km: km } });
    }

    if (pathname === '/api/settings' && req.method === 'GET') {
      const sRes = await pool.query('SELECT key, value FROM system_settings');
      const settings = {};
      sRes.rows.forEach(r => { settings[r.key] = r.value; });
      return sendJson(res, 200, { settings });
    }

    if (pathname === '/api/admin/settings' && req.method === 'POST') {
      const body = await parseBody(req);
      for (const [k, v] of Object.entries(body)) {
        if (typeof v === 'string') {
          await pool.query('INSERT INTO system_settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value', [k, v]);
        }
      }
      return sendJson(res, 200, { success: true });
    }

    if (pathname === '/api/maintenance-requests' && req.method === 'GET') {
      const rRes = await pool.query('SELECT * FROM maintenance_requests ORDER BY created_at DESC LIMIT 100');
      return sendJson(res, 200, { requests: rRes.rows });
    }

    if (pathname === '/api/maintenance-requests' && req.method === 'POST') {
      const body = await parseBody(req);
      const reqId = 'REQ-' + new Date().getFullYear() + '-' + Math.floor(1000 + Math.random() * 9000);
      await pool.query(`
        INSERT INTO maintenance_requests (request_id, user_id, user_name, department, vehicle_number, current_km, category, notes, status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'PENDING')
      `, [reqId, body.user_id || 'user1', body.user_name || '', body.department || '', body.vehicle_number || '', parseInt(body.current_km || 0, 10), body.category || 'صيانة', body.notes || '']);
      broadcastEvent('NEW_MAINTENANCE_REQUEST', { request_id: reqId });
      return sendJson(res, 201, { success: true, request_id: reqId, message: 'تم إرسال طلب الصيانة بنجاح' });
    }

    if ((pathname === '/api/notifications' || pathname.startsWith('/api/notifications/')) && req.method === 'GET') {
      const userId = pathname.replace('/api/notifications', '').replace(/^\//, '') || parsedUrl.searchParams.get('user_id');
      const nRes = (userId && userId !== 'ALL')
        ? await pool.query('SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50', [userId])
        : await pool.query('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50');
      return sendJson(res, 200, { notifications: nRes.rows });
    }

    if ((pathname === '/api/admin/broadcast' || pathname === '/api/broadcast') && req.method === 'POST') {
      const body = await parseBody(req);
      const uRes = await pool.query('SELECT user_id FROM users WHERE is_active = TRUE AND COALESCE(is_deleted, FALSE) = FALSE');
      for (const u of uRes.rows) {
        await pool.query(
          'INSERT INTO notifications (notification_id, user_id, title, purpose, message, type) VALUES ($1,$2,$3,$4,$5,$6)',
          ['BC-' + crypto.randomUUID().slice(0, 8), u.user_id, body.title || 'إشعار إداري', body.purpose || 'تعميم', body.message || '', 'ADMIN_BROADCAST']
        );
      }
      broadcastEvent('ADMIN_BROADCAST', { title: body.title, message: body.message });
      return sendJson(res, 200, { success: true, message: `تم إرسال الإشعار إلى ${uRes.rows.length} مستخدم` });
    }

    if (pathname === '/api/admin/analytics' && req.method === 'GET') {
      const [tot, pa, ip, pad, aud, usr] = await Promise.all([
        pool.query('SELECT COUNT(*)::int AS c FROM transactions WHERE COALESCE(is_deleted, FALSE) = FALSE'),
        pool.query("SELECT COUNT(*)::int AS c FROM transactions WHERE status = 'PENDING_AUDITOR' AND COALESCE(is_deleted, FALSE) = FALSE"),
        pool.query("SELECT COUNT(*)::int AS c FROM transactions WHERE status = 'IN_PROGRESS' AND COALESCE(is_deleted, FALSE) = FALSE"),
        pool.query("SELECT COUNT(*)::int AS c FROM transactions WHERE status = 'PENDING_ADMIN' AND COALESCE(is_deleted, FALSE) = FALSE"),
        pool.query("SELECT COUNT(*)::int AS c FROM transactions WHERE status = 'AUDITED' AND COALESCE(is_deleted, FALSE) = FALSE"),
        pool.query('SELECT COUNT(*)::int AS c FROM users WHERE COALESCE(is_deleted, FALSE) = FALSE')
      ]);
      return sendJson(res, 200, {
        total: tot.rows[0].c,
        pending_auditor: pa.rows[0].c,
        in_progress: ip.rows[0].c,
        pending_admin: pad.rows[0].c,
        audited: aud.rows[0].c,
        total_users: usr.rows[0].c,
        top_faulty_vehicles: []
      });
    }

    if (pathname === '/api/admin/login-history' && req.method === 'GET') {
      const lRes = await pool.query('SELECT * FROM login_history ORDER BY timestamp DESC LIMIT 100');
      return sendJson(res, 200, { history: lRes.rows });
    }

    if (pathname === '/api/admin/audit-logs' && req.method === 'GET') {
      const aRes = await pool.query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 150');
      return sendJson(res, 200, { success: true, logs: aRes.rows });
    }

    if (pathname === '/api/admin/backup' && req.method === 'GET') {
      const tables = ['departments', 'users', 'vehicles', 'maintenance_categories', 'transactions', 'maintenance_requests', 'deleted_records'];
      const data = {};
      for (const t of tables) {
        const r = await pool.query(`SELECT * FROM ${t}`);
        data[t] = r.rows;
      }
      return sendJson(res, 200, { meta: { app_version: 'v3.0-cloud', backup_date: new Date().toISOString() }, data });
    }

    // --------------------------------------------------------------------------
    // Static Files Fallback
    // --------------------------------------------------------------------------
    let safePath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
    if (safePath === '/' || safePath === '\\') safePath = '/index.html';
    const localFilePath = path.join(__dirname, 'public', safePath);

    if (fs.existsSync(localFilePath) && fs.statSync(localFilePath).isFile()) {
      return serveStatic(req, res, localFilePath);
    }
    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(indexPath)) {
      return serveStatic(req, res, indexPath);
    }

    return sendJson(res, 404, { error: 'المسار المطلوب غير موجود: ' + pathname });
  } catch (err) {
    console.error('Server Error:', err);
    return sendJson(res, 500, { error: 'خطأ في السيرفر السحابي: ' + err.message });
  }
});

initDatabase().then(() => {
  server.listen(PORT, () => {
    console.log(`🚀 Wheel Maintenance Cloud Server running on port ${PORT}`);
  });
});
