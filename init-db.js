require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' && !process.env.DATABASE_URL.includes('localhost') ? { rejectUnauthorized: false } : false
});

async function initDb() {
  console.log('Connecting to PostgreSQL database...');
  const client = await pool.connect();
  try {
    const sqlPath = path.join(__dirname, 'schema.sql');
    const sql = fs.readFileSync(sqlPath, 'utf8');
    console.log('Applying schema.sql to PostgreSQL...');
    await client.query(sql);
    console.log('Database initialized successfully with tables, indices, and initial seed accounts!');
  } catch (err) {
    console.error('Database initialization error:', err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

initDb();
