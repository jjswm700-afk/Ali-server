FROM node:20-alpine

WORKDIR /app

# تثبيت الحزم المطلوبة
COPY package*.json ./
RUN npm install --production

# نسخ كود المشروع
COPY . .

# إنشاء مجلد السجلات
RUN mkdir -p logs

EXPOSE 3000

CMD ["node", "server.js"]
