#!/bin/bash
# ==============================================================================
# سكربت التثبيت والتشغيل السحابي الشامل - خادم صيانة العجلات
# Automated Cloud Server Setup Script for Ubuntu 22.04 / 24.04 LTS
# ==============================================================================

set -e

echo "===================================================================="
echo "  بدء إعداد وتثبيت سيرفر صيانة العجلات السحابي (Cloud Setup)..."
echo "===================================================================="

# 1. تحديث حزم النظام الأساسية
echo "[1/7] تحديث مستودعات النظام وحزم الأمان..."
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y curl wget git build-essential ufw nginx certbot python3-certbot-nginx

# 2. تثبيت Node.js LTS (v20)
echo "[2/7] تثبيت Node.js v20 LTS..."
if ! command -v node &> /dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi
echo "Node.js Version: $(node -v)"
echo "NPM Version: $(npm -v)"

# 3. تثبيت وضبط قاعدة بيانات PostgreSQL
echo "[3/7] تثبيت وضبط قاعدة بيانات PostgreSQL..."
sudo apt-get install -y postgresql postgresql-contrib

# تشغيل وتفعيل خدمة PostgreSQL
sudo systemctl enable postgresql
sudo systemctl start postgresql

DB_NAME="wheel_maintenance_db"
DB_USER="wheel_admin"
DB_PASS="StrongPassword_2026"

echo "إنشاء قاعدة البيانات والمستخدم في PostgreSQL..."
sudo -u postgres psql -c "DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$DB_USER') THEN
    CREATE ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASS' CREATEDB;
  END IF;
END \$\$;"

sudo -u postgres psql -c "SELECT 'CREATE DATABASE $DB_NAME OWNER $DB_USER' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DB_NAME')\gexec"

# 4. تثبيت حزم المشروع وتطبيق المخطط
echo "[4/7] تثبيت حزم Node.js وتطبيق الجداول الأولية..."
npm install --production

# تطبيق schema.sql
if [ -f "schema.sql" ]; then
  PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -f schema.sql || true
fi

# 5. تثبيت وضبط مدير العمليات PM2
echo "[5/7] تثبيت وتشغيل السيرفر عبر PM2..."
sudo npm install -g pm2
mkdir -p logs

pm2 delete wheel-maintenance-api 2>/dev/null || true
pm2 start ecosystem.config.js
pm2 save
sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u $USER --hp $HOME || true

# 6. ضبط خادم الويب Nginx
echo "[6/7] إعداد Nginx Reverse Proxy..."
if [ -f "nginx.conf" ]; then
  sudo cp nginx.conf /etc/nginx/sites-available/wheel-api
  sudo ln -sf /etc/nginx/sites-available/wheel-api /etc/nginx/sites-enabled/
  sudo rm -f /etc/nginx/sites-enabled/default
  sudo nginx -t
  sudo systemctl reload nginx
fi

# 7. ضبط جدار الحماية UFW
echo "[7/7] تأمين السيرفر وتفعيل جدار الحماية (UFW)..."
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw --force enable

echo "===================================================================="
echo "  ✅ اكتمل تثبيت وتشغيل السيرفر السحابي بنجاح!"
echo "  السيرفر يعمل الآن على المنفذ 3000 متصلاً بـ PostgreSQL ومحمياً بـ Nginx."
echo "  لإصدار شهادة SSL مجانية، شغّل الأمر التالي:"
echo "    sudo certbot --nginx -d api.yourdomain.com"
echo "===================================================================="
