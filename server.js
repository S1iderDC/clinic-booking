const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'test-secret';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

let db;

function getDatabasePath() {
  const dbDir = process.env.PERSISTENCE_MOUNT || path.join(process.cwd(), 'database');
  if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
  return path.join(dbDir, 'clinic.db');
}

async function initDatabase() {
  db = await open({ filename: getDatabasePath(), driver: sqlite3.Database });
  
  await db.exec(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  )`);
  
  await db.exec(`CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slot_key TEXT NOT NULL UNIQUE,
    slot_date TEXT NOT NULL,
    slot_time TEXT NOT NULL,
    full_name TEXT NOT NULL,
    phone TEXT,
    email TEXT,
    channel TEXT DEFAULT 'site',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  await db.exec(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`);
  
  const adminCount = await db.get('SELECT COUNT(*) as count FROM admins');
  if (adminCount.count === 0) {
    const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 10);
    await db.run('INSERT INTO admins (username, password_hash) VALUES (?, ?)', 
      [process.env.ADMIN_USERNAME || 'admin', hashedPassword]);
    console.log('Администратор создан');
  }
  console.log('База данных готова');
}

function isDatePast(dateStr) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const checkDate = new Date(dateStr);
  checkDate.setHours(0, 0, 0, 0);
  return checkDate < today;
}

async function generateSlotsForDate(date) {
  const slots = [];
  const bookedSlots = await db.all('SELECT slot_key FROM bookings WHERE slot_date = ?', [date]);
  const bookedKeys = new Set(bookedSlots.map(b => b.slot_key));
  
  for (let hour = 8; hour <= 23; hour++) {
    for (let minute = 0; minute < 60; minute += 10) {
      if (hour === 23 && minute > 50) break;
      const time = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`;
      const key = `${date}T${time}`;
      slots.push({ key, date, time, booked: bookedKeys.has(key) });
    }
  }
  return slots;
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Недействительный токен' });
    req.user = user;
    next();
  });
}

app.get('/api/slots/:date', async (req, res) => {
  try {
    const slots = await generateSlotsForDate(req.params.date);
    res.json({ date: req.params.date, slots });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения слотов' });
  }
});

app.get('/api/form-links', async (req, res) => {
  try {
    const googleUrl = await db.get("SELECT value FROM settings WHERE key = 'google_form_url'");
    const yandexUrl = await db.get("SELECT value FROM settings WHERE key = 'yandex_form_url'");
    res.json({ googleFormUrl: googleUrl?.value || '', yandexFormUrl: yandexUrl?.value || '' });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения ссылок' });
  }
});

app.post('/api/bookings', async (req, res) => {
  const { slotKey, fullName, phone, email } = req.body;
  try {
    const existing = await db.get('SELECT id FROM bookings WHERE slot_key = ?', [slotKey]);
    if (existing) return res.status(409).json({ error: 'Это время уже занято' });
    const [slotDate, slotTime] = slotKey.split('T');
    await db.run(`INSERT INTO bookings (slot_key, slot_date, slot_time, full_name, phone, email)
      VALUES (?, ?, ?, ?, ?, ?)`, [slotKey, slotDate, slotTime, fullName, phone || null, email || null]);
    res.status(201).json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка при создании записи' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const admin = await db.get('SELECT * FROM admins WHERE username = ?', [username]);
    if (!admin) return res.status(401).json({ error: 'Неверные данные' });
    const isValid = await bcrypt.compare(password, admin.password_hash);
    if (!isValid) return res.status(401).json({ error: 'Неверные данные' });
    const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ success: true, token, username: admin.username });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка входа' });
  }
});

app.get('/api/admin/me', authenticateToken, async (req, res) => {
  res.json({ isAdmin: true, username: req.user.username });
});

app.post('/api/admin/logout', authenticateToken, async (req, res) => {
  res.json({ success: true });
});

app.get('/api/admin/bookings', authenticateToken, async (req, res) => {
  try {
    const bookings = await db.all('SELECT * FROM bookings ORDER BY slot_date ASC, slot_time ASC');
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения записей' });
  }
});

app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  try {
    const total = await db.get('SELECT COUNT(*) as total FROM bookings');
    const today = new Date().toISOString().split('T')[0];
    const todayBookings = await db.get('SELECT COUNT(*) as count FROM bookings WHERE slot_date = ?', [today]);
    res.json({ total: total.total, today: todayBookings.count });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения статистики' });
  }
});

app.get('/api/admin/bookings.csv', authenticateToken, async (req, res) => {
  const bookings = await db.all('SELECT * FROM bookings ORDER BY slot_date ASC, slot_time ASC');
  let csv = 'ID,Дата,Время,ФИО,Телефон,Email,Канал,Дата создания\n';
  for (const b of bookings) {
    csv += `${b.id},${b.slot_date},${b.slot_time},"${b.full_name}",${b.phone || ''},${b.email || ''},${b.channel},${b.created_at}\n`;
  }
  res.setHeader('Content-Type', 'text/csv');
  res.send('\uFEFF' + csv);
});

app.put('/api/admin/form-links', authenticateToken, async (req, res) => {
  const { googleFormUrl, yandexFormUrl } = req.body;
  await db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, ['google_form_url', googleFormUrl || '']);
  await db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, ['yandex_form_url', yandexFormUrl || '']);
  res.json({ success: true });
});

app.delete('/api/admin/bookings/:id', authenticateToken, async (req, res) => {
  await db.run('DELETE FROM bookings WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

initDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен на порту ${PORT}`);
  });
}).catch(console.error);