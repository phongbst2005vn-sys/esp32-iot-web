const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./iot_platform.db');

db.serialize(() => {
    // 1. Bảng Tài khoản người dùng (thêm cột role: 'admin' hoặc 'user')
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tự động bổ sung cột role nếu database cũ đã tồn tại
    db.run(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'`, () => {});
    db.run(`ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP`, () => {});

    // 2. Bảng Dự án
    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        description TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // 3. Bảng Thiết bị ESP32
    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER,
        name TEXT,
        device_token TEXT UNIQUE,
        FOREIGN KEY(project_id) REFERENCES projects(id)
    )`);

    // 4. Bảng Cấu hình chân GPIO
    db.run(`CREATE TABLE IF NOT EXISTS device_pins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER,
        category TEXT,
        name TEXT,
        type TEXT,
        gpio INTEGER,
        unit TEXT,
        min_val INTEGER DEFAULT 0,
        max_val INTEGER DEFAULT 255,
        FOREIGN KEY(device_id) REFERENCES devices(id)
    )`);
});

console.log("✅ Database SQLite (Hỗ trợ Admin & Xóa dự án) đã sẵn sàng!");
module.exports = db;