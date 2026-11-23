-- ==============================================================================
-- مخطط قاعدة بيانات PostgreSQL المركزية - نظام إدارة وصيانة العجلات
-- Wheel Maintenance Central PostgreSQL Database Schema (Cloud Edition)
-- ==============================================================================

-- 1. جدول الأقسام الإدارية (Departments)
CREATE TABLE IF NOT EXISTS departments (
    department_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50),
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMPTZ,
    deleted_by VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. جدول المستخدمين (Users & Permissions)
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    department_id VARCHAR(64) REFERENCES departments(department_id) ON DELETE SET NULL,
    unit VARCHAR(255) DEFAULT '',
    role VARCHAR(50) DEFAULT 'USER' CHECK (role IN ('USER', 'AUDITOR', 'ADMIN', 'DEPARTMENT_HEAD', 'Department_Head')),
    is_active BOOLEAN DEFAULT TRUE,
    is_read_only BOOLEAN DEFAULT FALSE,
    can_add_transaction BOOLEAN DEFAULT TRUE,
    is_department_manager BOOLEAN DEFAULT FALSE,
    assigned_department_id VARCHAR(64) REFERENCES departments(department_id) ON DELETE SET NULL,
    can_add_dept_members_transactions BOOLEAN DEFAULT FALSE,
    can_edit_dept_transactions BOOLEAN DEFAULT FALSE,
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMPTZ,
    deleted_by VARCHAR(64),
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. جدول العجلات والآليات (Vehicles Fleet)
CREATE TABLE IF NOT EXISTS vehicles (
    vehicle_id VARCHAR(64) PRIMARY KEY,
    plate_number VARCHAR(100) UNIQUE NOT NULL,
    vehicle_type VARCHAR(100) DEFAULT 'عجلة صالون / نقل',
    department_id VARCHAR(64) REFERENCES departments(department_id) ON DELETE SET NULL,
    current_km INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMPTZ,
    deleted_by VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. جدول معاملات الصيانة والمشتريات (Maintenance Transactions)
CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    transaction_id VARCHAR(64) UNIQUE NOT NULL,
    wheel_id VARCHAR(100),
    vehicle_numbers JSONB DEFAULT '[]'::jsonb,
    department_id VARCHAR(64) REFERENCES departments(department_id) ON DELETE SET NULL,
    user_id VARCHAR(64) REFERENCES users(user_id) ON DELETE SET NULL,
    member_user_id VARCHAR(64) REFERENCES users(user_id) ON DELETE SET NULL,
    created_by VARCHAR(64) REFERENCES users(user_id) ON DELETE SET NULL,
    updated_by VARCHAR(64),
    description TEXT,
    cost NUMERIC(15, 2) DEFAULT 0.00,
    mileage INT DEFAULT 0,
    receipt_image TEXT,
    receipt_images JSONB DEFAULT '[]'::jsonb,
    vehicle_images JSONB DEFAULT '[]'::jsonb,
    category VARCHAR(100) DEFAULT 'إطارات وبطاريات',
    status VARCHAR(50) DEFAULT 'PENDING_AUDITOR' CHECK (status IN ('PENDING_AUDITOR', 'IN_PROGRESS', 'PENDING_ADMIN', 'AUDITED', 'REJECTED')),
    is_locked BOOLEAN DEFAULT TRUE,
    auditor_note TEXT,
    admin_note TEXT,
    audited_by_auditor_at TIMESTAMPTZ,
    audited_at TIMESTAMPTZ,
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMPTZ,
    deleted_by VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. جدول تأكيدات القراءة للإشعارات (Notification Read Receipts)
CREATE TABLE IF NOT EXISTS notification_read_receipts (
    id SERIAL PRIMARY KEY,
    notification_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    user_name VARCHAR(255),
    seen_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. جدول سجل التدقيق الأمني (Audit Logs)
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100),
    entity_id VARCHAR(100),
    actor_id VARCHAR(64),
    actor_name VARCHAR(255),
    details JSONB,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 7. جدول سلة المحذوفات للأرشفة الآمنة (Deleted Records Archive)
CREATE TABLE IF NOT EXISTS deleted_records (
    id SERIAL PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(100) NOT NULL,
    record_snapshot JSONB NOT NULL,
    deleted_by VARCHAR(255),
    deleted_at TIMESTAMPTZ DEFAULT NOW()
);

-- فهارس تحسين الأداء (Indexes)
CREATE INDEX IF NOT EXISTS idx_trans_user ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_trans_dept ON transactions(department_id);
CREATE INDEX IF NOT EXISTS idx_trans_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_trans_deleted ON transactions(is_deleted);
CREATE INDEX IF NOT EXISTS idx_trans_created ON transactions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_notif_receipts ON notification_read_receipts(notification_id, user_id);

-- ==============================================================================
-- البيانات الأولية الأساسية (Initial Seed Data)
-- كلمة المرور الافتراضية للحسابات هي 123 (مشفرة بـ sha256 أو bcrypt)
-- ==============================================================================

-- إضافة الأقسام الأساسية
INSERT INTO departments (department_id, name, code) VALUES
('DEPT-000', 'إدارة الصيانة والآليات المركزية', 'ADMIN_HQ'),
('DEPT-001', 'قسم النقل والآليات', 'TRANS_FLEET'),
('DEPT-002', 'قسم الخدمات والآليات التخصصية', 'SPEC_FLEET'),
('DEPT-003', 'شعبة التدقيق والرقابة المالية', 'AUDIT_DIV'),
('DEPT-004', 'قسم الخدمات الإدارية', 'ADMIN_SERV')
ON CONFLICT (department_id) DO NOTHING;

-- إضافة الحسابات الإدارية الأساسية (كلمة المرور 123)
-- التجزئة: a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3 (sha256 لـ 123)
INSERT INTO users (
    user_id, username, password_hash, full_name, department_id, unit, role, 
    is_active, is_read_only, can_add_transaction, is_department_manager, 
    assigned_department_id, can_add_dept_members_transactions, can_edit_dept_transactions
) VALUES
('USR-ADMIN-001', 'admin', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 'المهندس أحمد مصطفى (مدير النظام والرقابة)', 'DEPT-000', 'الإدارة العامة', 'ADMIN', TRUE, FALSE, TRUE, FALSE, NULL, TRUE, TRUE),
('USR-AUDITOR-001', 'auditor1', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 'مدقق الوصولات المعتمد', 'DEPT-003', 'شعبة التدقيق والرقابة المالية', 'AUDITOR', TRUE, FALSE, FALSE, FALSE, NULL, FALSE, FALSE),
('USR-HEAD-001', 'head1', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 'الأستاذ حيدر الكعبي (مسؤول قسم النقل والآليات)', 'DEPT-001', 'قسم النقل والآليات', 'Department_Head', TRUE, FALSE, TRUE, TRUE, 'DEPT-001', TRUE, TRUE),
('USR-FIELD-001', 'user1', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 'حيدر علي عبد الحسين', 'DEPT-001', 'شعبة الحركة الميدانية', 'USER', TRUE, FALSE, TRUE, FALSE, NULL, FALSE, FALSE)
ON CONFLICT (username) DO NOTHING;

-- إضافة عجلات أولية للاختبار
INSERT INTO vehicles (vehicle_id, plate_number, vehicle_type, department_id, current_km, is_active) VALUES
('VEH-0001', 'بغداد 12345 خصوصي', 'صالون تويوتا كورولا', 'DEPT-001', 124500, TRUE),
('VEH-0002', 'بابل 67890 خصوصي', 'بيك آب نيسان نافارا', 'DEPT-001', 89200, TRUE),
('VEH-0003', 'بغداد 55432 نقل', 'حافلة هيونداي كاونتي', 'DEPT-002', 215000, TRUE)
ON CONFLICT (plate_number) DO NOTHING;
