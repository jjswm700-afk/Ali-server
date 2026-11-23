module.exports = {
  apps: [
    {
      name: "wheel-maintenance-api",
      script: "./server.js",
      instances: "max",       // تشغيل بعدد أنوية المعالج (Cluster Mode) لأعلى أداء
      exec_mode: "cluster",
      watch: false,
      max_memory_restart: "500M",
      env: {
        NODE_ENV: "production",
        PORT: 3000
      },
      error_file: "./logs/pm2-err.log",
      out_file: "./logs/pm2-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
      autorestart: true,
      restart_delay: 4000
    }
  ]
};
