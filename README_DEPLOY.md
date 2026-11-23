# دليل التشغيل والرفع السحابي الشامل - برنامج صيانة العجلات
## Complete Cloud Server Setup & Deployment Guide

> هذا الدليل مصمم لمهندس السيرفرات والمطور لتشغيل خادم النظام السحابي وقاعدة بيانات PostgreSQL المركزية على سيرفر افتراضي (VPS) متصل بالإنترنت ومؤمن بـ HTTPS.

---

### الفهرس
1. [متطلبات السيرفر والنطاق (Prerequisites)](#1-متطلبات-السيرفر-والنطاق)
2. [الطريقة الأولى: التثبيت التلقائي المباشر (Automated Ubuntu Setup)](#2-الطريقة-الأولى-التثبيت-التلقائي-المباشر)
3. [الطريقة الثانية: التشغيل عبر حاويات Docker (Docker Compose)](#3-الطريقة-الثانية-التشغيل-عبر-حاويات-docker)
4. [إصدار شهادة الأمان HTTPS / SSL](#4-إصدار-شهادة-الأمان-https--ssl)
5. [ربط تطبيق الهاتف وموقع الويب بالسيرفر السحابي](#5-ربط-تطبيق-الهاتف-وموقع-الويب-بالسيرفر-السحابي)
6. [فحص التشغيل والتحقق (Verification Checklist)](#6-فحص-التشغيل-والتحقق)

---

### 1. متطلبات السيرفر والنطاق

* **السيرفر (VPS):** خادم من مزود مثل (Hetzner, DigitalOcean, Linode, AWS Lightsail, Contabo).
  * نظام التشغيل: `Ubuntu 22.04 LTS` أو `Ubuntu 24.04 LTS`.
  * المواصفات: 2 vCPU و 2GB - 4GB RAM.
* **النطاق (Domain Name):**
  * إضافة سجل `A Record` في لوحة تحكم النطاق (Cloudflare, GoDaddy, إلخ):
    * **Type:** `A`
    * **Name:** `api` (ليصبح `api.yourdomain.com`)
    * **Value / Target:** عنوان الـ IP العام للسيرفر (Public IPv4)
    * **TTL:** Automatic أو 300

---

### 2. الطريقة الأولى: التثبيت التلقائي المباشر (Recommended)

1. **نسخ ملفات مجلد `cloud_server` إلى السيرفر:**
   ```bash
   scp -r cloud_server/* user@YOUR_SERVER_IP:/var/www/wheel-api/
   ```

2. **الدخول عبر SSH:**
   ```bash
   ssh user@YOUR_SERVER_IP
   cd /var/www/wheel-api/
   ```

3. **منح صلاحية التنفيذ للسكربت وتشغيله:**
   ```bash
   chmod +x deploy.sh
   ./deploy.sh
   ```
   *يقوم السكربت آلياً بتحديث النظام، وتثبيت Node.js v20، وتثبيت وضبط PostgreSQL، واستيراد الجداول الأولية، وإعداد PM2 و Nginx وجدار الحماية UFW.*

---

### 3. الطريقة الثانية: التشغيل عبر حاويات Docker

إذا كنت تفضل استخدام Docker و Docker Compose:

```bash
cd /var/www/wheel-api/
sudo docker compose up -d --build
```

سيتم تشغيل حاوية الـ API وحاوية PostgreSQL 16 Alpine تلقائياً مع حجم تخزين دائم (`pgdata`).

---

### 4. إصدار شهادة الأمان HTTPS / SSL

بعد توجيه النطاق للسيرفر، يتم تشغيل الأمر التالي لإصدار شهادة SSL مشفرة مجانية من Let's Encrypt وتفعيل التجديد التلقائي:

```bash
sudo certbot --nginx -d api.yourdomain.com
```

اختر تحويل الترافيك التلقائي إلى HTTPS (Redirect HTTP to HTTPS).

---

### 5. ربط تطبيق الهاتف وموقع الويب بالسيرفر السحابي

#### أ) في تطبيق Flutter (`flutter_app`):
الملف: `lib/services/api_service.dart`
```dart
static const String baseUrl = 'https://api.yourdomain.com/api';
```

#### ب) في تطبيق الويب والأندرويد الهجين (`index.html`):
اضغط على زر **"سيرفر التزامن: متصل سحابياً"** في شاشة تسجيل الدخول وأدخل الرابط:
`https://api.yourdomain.com/api` وسيتم حفظه محلياً في الذاكرة ومزامنة كافة العمليات تلقائياً عند توفر الإنترنت.

---

### 6. فحص التشغيل والتحقق

1. **فحص رابط الحالة:**
   ```bash
   curl -I https://api.yourdomain.com/api/health
   # النتيجة المتوقعة: HTTP/2 200 OK
   ```

2. **فحص العمليات العاملة في PM2:**
   ```bash
   pm2 status
   pm2 logs wheel-maintenance-api
   ```

3. **فحص جدار الحماية:**
   ```bash
   sudo ufw status
   # المنافذ المفتوحة: 22 (SSH), 80 (HTTP), 443 (HTTPS)
   ```
