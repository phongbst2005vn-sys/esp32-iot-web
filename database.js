const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

pool.connect()
    .then(() => console.log("✅ Đã kết nối thành công tới Supabase PostgreSQL!"))
    .catch(err => console.error("❌ Lỗi kết nối Supabase:", err.message));

module.exports = pool;