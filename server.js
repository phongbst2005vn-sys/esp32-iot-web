const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');
const db = require('./database');

const app = express();
const SECRET_KEY = process.env.SECRET_KEY || "esp32_iot_secret_key_change_me";

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Chưa đăng nhập" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Phiên đăng nhập hết hạn" });
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Chỉ tài khoản Quản trị Admin mới có quyền này!" });
    }
    next();
}

// --- AUTH API ---
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Vui lòng nhập đủ thông tin!" });
    
    // Tài khoản đầu tiên tạo trên hệ thống hoặc tên 'admin' sẽ tự động được cấp quyền Admin
    db.get(`SELECT COUNT(*) as count FROM users`, [], (err, row) => {
        const role = (row && row.count === 0) || username.toLowerCase() === 'admin' ? 'admin' : 'user';
        const hashedPassword = bcrypt.hashSync(password, 8);
        db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, [username, hashedPassword, role], function(err) {
            if (err) return res.status(400).json({ error: "Tên tài khoản đã tồn tại!" });
            res.json({ message: `Đăng ký thành công! (Quyền: ${role.toUpperCase()})` });
        });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password, loginAs } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: "Sai tài khoản hoặc mật khẩu!" });
        }
        const userRole = user.role || (user.username.toLowerCase() === 'admin' ? 'admin' : 'user');
        if (loginAs === 'admin' && userRole !== 'admin') {
            return res.status(403).json({ error: "Tài khoản này không có quyền Quản trị Admin!" });
        }
        const token = jwt.sign({ id: user.id, username: user.username, role: userRole }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ token, username: user.username, role: userRole });
    });
});

// --- ADMIN API (THEO DÕI NGƯỜI DÙNG & DỰ ÁN TOÀN HỆ THỐNG) ---
app.get('/api/admin/overview', authenticateToken, requireAdmin, (req, res) => {
    db.all(`SELECT id, username, role, created_at FROM users ORDER BY id ASC`, [], (err, users) => {
        db.all(`SELECT * FROM projects`, [], (err, projects) => {
            db.all(`SELECT * FROM devices`, [], (err, devices) => {
                const enrichedUsers = (users || []).map(u => {
                    const userProjects = (projects || []).filter(p => p.user_id === u.id).map(p => ({
                        ...p,
                        devices: (devices || []).filter(d => d.project_id === p.id)
                    }));
                    return { ...u, projects: userProjects };
                });
                res.json({
                    totalUsers: (users || []).length,
                    totalProjects: (projects || []).length,
                    totalDevices: (devices || []).length,
                    users: enrichedUsers
                });
            });
        });
    });
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    const targetId = Number(req.params.id);
    if (targetId === req.user.id) return res.status(400).json({ error: "Không thể tự xóa chính tài khoản Admin đang dùng!" });

    db.all(`SELECT id FROM projects WHERE user_id = ?`, [targetId], (err, projs) => {
        const projIds = (projs || []).map(p => p.id);
        if (projIds.length > 0) {
            const ph = projIds.map(() => '?').join(',');
            db.run(`DELETE FROM device_pins WHERE device_id IN (SELECT id FROM devices WHERE project_id IN (${ph}))`, projIds);
            db.run(`DELETE FROM devices WHERE project_id IN (${ph})`, projIds);
            db.run(`DELETE FROM projects WHERE user_id = ?`, [targetId]);
        }
        db.run(`DELETE FROM users WHERE id = ?`, [targetId], () => res.json({ deleted: true }));
    });
});

// --- PROJECTS, DEVICES & PINS API ---
app.get('/api/projects', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM projects WHERE user_id = ?`, [req.user.id], (err, projects) => {
        if (!projects || projects.length === 0) return res.json([]);
        const projectIds = projects.map(p => p.id);
        const pPlaceholders = projectIds.map(() => '?').join(',');

        db.all(`SELECT * FROM devices WHERE project_id IN (${pPlaceholders})`, projectIds, (err, devices) => {
            if (!devices || devices.length === 0) {
                return res.json(projects.map(p => ({ ...p, devices: [] })));
            }
            const deviceIds = devices.map(d => d.id);
            const dPlaceholders = deviceIds.map(() => '?').join(',');

            db.all(`SELECT * FROM device_pins WHERE device_id IN (${dPlaceholders})`, deviceIds, (err, pins) => {
                const enrichedDevices = devices.map(d => ({
                    ...d,
                    pins: (pins || []).filter(pin => pin.device_id === d.id)
                }));
                const result = projects.map(p => ({
                    ...p,
                    devices: enrichedDevices.filter(d => d.project_id === p.id)
                }));
                res.json(result);
            });
        });
    });
});

app.post('/api/projects', authenticateToken, (req, res) => {
    const { name, description } = req.body;
    db.run(`INSERT INTO projects (user_id, name, description) VALUES (?, ?, ?)`, 
        [req.user.id, name, description], function(err) {
        res.json({ id: this.lastID, name, description, devices: [] });
    });
});

// API XÓA DỰ ÁN (Xóa sạch thiết bị và chân GPIO thuộc dự án đó)
app.delete('/api/projects/:id', authenticateToken, (req, res) => {
    const projectId = req.params.id;
    db.get(`SELECT * FROM projects WHERE id = ? AND user_id = ?`, [projectId, req.user.id], (err, proj) => {
        if (!proj) return res.status(404).json({ error: "Không tìm thấy dự án!" });
        db.run(`DELETE FROM device_pins WHERE device_id IN (SELECT id FROM devices WHERE project_id = ?)`, [projectId]);
        db.run(`DELETE FROM devices WHERE project_id = ?`, [projectId]);
        db.run(`DELETE FROM projects WHERE id = ?`, [projectId], () => {
            res.json({ deleted: true });
        });
    });
});

app.post('/api/projects/:projectId/devices', authenticateToken, (req, res) => {
    const { name } = req.body;
    const deviceToken = "esp32_" + crypto.randomBytes(6).toString('hex');
    db.run(`INSERT INTO devices (project_id, name, device_token) VALUES (?, ?, ?)`,
        [req.params.projectId, name, deviceToken], function(err) {
        res.json({ id: this.lastID, name, device_token: deviceToken, pins: [] });
    });
});

// API XÓA THIẾT BỊ ESP32
app.delete('/api/devices/:id', authenticateToken, (req, res) => {
    const deviceId = req.params.id;
    db.run(`DELETE FROM device_pins WHERE device_id = ?`, [deviceId]);
    db.run(`DELETE FROM devices WHERE id = ?`, [deviceId], () => {
        res.json({ deleted: true });
    });
});

app.post('/api/devices/:deviceId/pins', authenticateToken, (req, res) => {
    const { category, name, type, gpio, unit, min_val, max_val } = req.body;
    db.run(`INSERT INTO device_pins (device_id, category, name, type, gpio, unit, min_val, max_val) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.params.deviceId, category, name, type, Number(gpio), unit || '', min_val || 0, max_val || 255], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, device_id: Number(req.params.deviceId), category, name, type, gpio: Number(gpio), unit, min_val, max_val });
    });
});

app.delete('/api/pins/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM device_pins WHERE id = ?`, [req.params.id], function(err) {
        res.json({ deleted: true });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy tại cổng: ${PORT}`);
});