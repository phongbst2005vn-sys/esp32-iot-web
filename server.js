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
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: "Vui lòng nhập đủ thông tin!" });

        const countRes = await db.query(`SELECT COUNT(*)::int AS count FROM users`);
        const isFirstUser = countRes.rows[0].count === 0;
        const role = (isFirstUser || username.toLowerCase() === 'admin') ? 'admin' : 'user';
        const hashedPassword = bcrypt.hashSync(password, 8);

        await db.query(
            `INSERT INTO users (username, password, role) VALUES ($1, $2, $3)`,
            [username, hashedPassword, role]
        );
        res.json({ message: `Đăng ký thành công! (Quyền: ${role.toUpperCase()})` });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Tên tài khoản đã tồn tại!" });
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password, loginAs } = req.body;
        const result = await db.query(`SELECT * FROM users WHERE username = $1`, [username]);
        const user = result.rows[0];

        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: "Sai tài khoản hoặc mật khẩu!" });
        }
        const userRole = user.role || (user.username.toLowerCase() === 'admin' ? 'admin' : 'user');
        if (loginAs === 'admin' && userRole !== 'admin') {
            return res.status(403).json({ error: "Tài khoản này không có quyền Quản trị Admin!" });
        }
        const token = jwt.sign({ id: user.id, username: user.username, role: userRole }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ token, username: user.username, role: userRole });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ADMIN API ---
app.get('/api/admin/overview', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const usersRes = await db.query(`SELECT id, username, role, created_at FROM users ORDER BY id ASC`);
        const projectsRes = await db.query(`SELECT * FROM projects ORDER BY id ASC`);
        const devicesRes = await db.query(`SELECT * FROM devices ORDER BY id ASC`);

        const users = usersRes.rows;
        const projects = projectsRes.rows;
        const devices = devicesRes.rows;

        const enrichedUsers = users.map(u => {
            const userProjects = projects.filter(p => p.user_id === u.id).map(p => ({
                ...p,
                devices: devices.filter(d => d.project_id === p.id)
            }));
            return { ...u, projects: userProjects };
        });

        res.json({
            totalUsers: users.length,
            totalProjects: projects.length,
            totalDevices: devices.length,
            users: enrichedUsers
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const targetId = Number(req.params.id);
        if (targetId === req.user.id) return res.status(400).json({ error: "Không thể tự xóa tài khoản Admin đang dùng!" });
        await db.query(`DELETE FROM users WHERE id = $1`, [targetId]);
        res.json({ deleted: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- PROJECTS, DEVICES & PINS API ---
app.get('/api/projects', authenticateToken, async (req, res) => {
    try {
        const projRes = await db.query(`SELECT * FROM projects WHERE user_id = $1 ORDER BY id ASC`, [req.user.id]);
        const projects = projRes.rows;
        if (projects.length === 0) return res.json([]);

        const projectIds = projects.map(p => p.id);
        const devRes = await db.query(`SELECT * FROM devices WHERE project_id = ANY($1::int[]) ORDER BY id ASC`, [projectIds]);
        const devices = devRes.rows;

        if (devices.length === 0) {
            return res.json(projects.map(p => ({ ...p, devices: [] })));
        }

        const deviceIds = devices.map(d => d.id);
        const pinRes = await db.query(`SELECT * FROM device_pins WHERE device_id = ANY($1::int[]) ORDER BY id ASC`, [deviceIds]);
        const pins = pinRes.rows;

        const enrichedDevices = devices.map(d => ({
            ...d,
            pins: pins.filter(pin => pin.device_id === d.id)
        }));
        const result = projects.map(p => ({
            ...p,
            devices: enrichedDevices.filter(d => d.project_id === p.id)
        }));
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/projects', authenticateToken, async (req, res) => {
    try {
        const { name, description } = req.body;
        const result = await db.query(
            `INSERT INTO projects (user_id, name, description) VALUES ($1, $2, $3) RETURNING id`,
            [req.user.id, name, description]
        );
        res.json({ id: result.rows[0].id, name, description, devices: [] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/projects/:id', authenticateToken, async (req, res) => {
    try {
        const result = await db.query(`DELETE FROM projects WHERE id = $1 AND user_id = $2`, [req.params.id, req.user.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: "Không tìm thấy dự án!" });
        res.json({ deleted: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/projects/:projectId/devices', authenticateToken, async (req, res) => {
    try {
        const { name } = req.body;
        const deviceToken = "esp32_" + crypto.randomBytes(6).toString('hex');
        const result = await db.query(
            `INSERT INTO devices (project_id, name, device_token) VALUES ($1, $2, $3) RETURNING id`,
            [req.params.projectId, name, deviceToken]
        );
        res.json({ id: result.rows[0].id, name, device_token: deviceToken, pins: [] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/devices/:id', authenticateToken, async (req, res) => {
    try {
        await db.query(`DELETE FROM devices WHERE id = $1`, [req.params.id]);
        res.json({ deleted: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/devices/:deviceId/pins', authenticateToken, async (req, res) => {
    try {
        const { category, name, type, gpio, unit, min_val, max_val } = req.body;
        const result = await db.query(
            `INSERT INTO device_pins (device_id, category, name, type, gpio, unit, min_val, max_val) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
            [req.params.deviceId, category, name, type, Number(gpio), unit || '', Number(min_val) || 0, Number(max_val) || 255]
        );
        res.json({
            id: result.rows[0].id,
            device_id: Number(req.params.deviceId),
            category, name, type,
            gpio: Number(gpio), unit, min_val, max_val
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/pins/:id', authenticateToken, async (req, res) => {
    try {
        await db.query(`DELETE FROM device_pins WHERE id = $1`, [req.params.id]);
        res.json({ deleted: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server đang chạy tại cổng: ${PORT}`);
});