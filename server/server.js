const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { init: initDb } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

let db; // will be set after async init

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));
app.use(session({
  secret: 'taskline-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// ─── Auth Helpers ─────────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'נדרשת התחברות' });
  next();
}

function requireProvider(req, res, next) {
  if (!req.session.userId || req.session.role !== 'provider') {
    return res.status(403).json({ error: 'גישה לנותני שירות בלבד' });
  }
  next();
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  const { name, email, username, password, role, service_type } = req.body;

  if (!name || !email || !username || !password || !role) {
    return res.status(400).json({ error: 'כל השדות חובה' });
  }
  if (!['provider', 'requester'].includes(role)) {
    return res.status(400).json({ error: 'תפקיד לא תקין' });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    const stmt = db.prepare(
      'INSERT INTO users (name, email, username, password, role, service_type) VALUES (?, ?, ?, ?, ?, ?)'
    );
    const result = stmt.run(
      name, email.toLowerCase(), username.toLowerCase(),
      hashed, role, service_type || 'אחר'
    );

    req.session.userId = result.lastInsertRowid;
    req.session.role = role;
    req.session.username = username.toLowerCase();
    req.session.name = name;

    res.json({ success: true, role, username: username.toLowerCase() });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      const field = err.message.includes('email') ? 'אימייל' : 'שם משתמש';
      return res.status(400).json({ error: `ה${field} הזה כבר קיים במערכת` });
    }
    res.status(500).json({ error: 'שגיאת שרת' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'שם משתמש וסיסמה נדרשים' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());
  if (!user) return res.status(401).json({ error: 'פרטי התחברות שגויים' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'פרטי התחברות שגויים' });

  req.session.userId = user.id;
  req.session.role = user.role;
  req.session.username = user.username;
  req.session.name = user.name;

  res.json({ success: true, role: user.role, username: user.username });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });

  const user = db.prepare('SELECT id, name, username, role, service_type FROM users WHERE id = ?')
    .get(req.session.userId);

  res.json({
    loggedIn: true,
    userId: req.session.userId,
    role: req.session.role,
    username: req.session.username,
    name: req.session.name,
    service_type: user?.service_type || 'אחר'
  });
});

// ─── Providers List (public) ──────────────────────────────────────────────────

app.get('/api/providers', (req, res) => {
  const providers = db.prepare(`
    SELECT id, name, username, service_type FROM users
    WHERE role = 'provider'
    ORDER BY name ASC
  `).all();

  const enriched = providers.map(p => {
    const waiting = db.prepare(`
      SELECT COUNT(*) as count FROM tasks
      WHERE provider_id = ? AND status IN ('waiting', 'in_progress')
    `).get(p.id).count;
    return { ...p, waitingCount: waiting };
  });

  res.json(enriched);
});

// ─── Provider Queue Routes ────────────────────────────────────────────────────

app.get('/api/queue/provider', requireProvider, (req, res) => {
  const tasks = db.prepare(`
    SELECT t.*, s.date as slot_date, s.time as slot_time, s.duration as slot_duration
    FROM tasks t
    LEFT JOIN slots s ON t.slot_id = s.id
    WHERE t.provider_id = ? AND t.status != 'done'
    ORDER BY t.queue_position ASC, t.created_at ASC
  `).all(req.session.userId);

  const done = db.prepare(`
    SELECT t.*, s.date as slot_date, s.time as slot_time
    FROM tasks t
    LEFT JOIN slots s ON t.slot_id = s.id
    WHERE t.provider_id = ? AND t.status = 'done'
    ORDER BY t.done_at DESC
    LIMIT 10
  `).all(req.session.userId);

  const provider = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

  res.json({ active: tasks, done, provider });
});

app.post('/api/queue/start/:id', requireProvider, (req, res) => {
  const task = db.prepare('SELECT * FROM tasks WHERE id = ? AND provider_id = ?')
    .get(req.params.id, req.session.userId);

  if (!task) return res.status(404).json({ error: 'משימה לא נמצאה' });
  if (task.status === 'done') return res.status(400).json({ error: 'משימה כבר טופלה' });

  db.prepare(`UPDATE tasks SET status = 'in_progress', started_at = CURRENT_TIMESTAMP WHERE id = ?`)
    .run(req.params.id);

  res.json({ success: true });
});

app.post('/api/queue/done/:id', requireProvider, (req, res) => {
  const task = db.prepare('SELECT * FROM tasks WHERE id = ? AND provider_id = ?')
    .get(req.params.id, req.session.userId);

  if (!task) return res.status(404).json({ error: 'משימה לא נמצאה' });

  db.prepare(`UPDATE tasks SET status = 'done', done_at = CURRENT_TIMESTAMP WHERE id = ?`)
    .run(req.params.id);

  recalculatePositions(req.session.userId);
  res.json({ success: true });
});

app.post('/api/queue/skip/:id', requireProvider, (req, res) => {
  const task = db.prepare('SELECT * FROM tasks WHERE id = ? AND provider_id = ?')
    .get(req.params.id, req.session.userId);

  if (!task) return res.status(404).json({ error: 'משימה לא נמצאה' });

  const maxPos = db.prepare(`
    SELECT MAX(queue_position) as max FROM tasks
    WHERE provider_id = ? AND status = 'waiting'
  `).get(req.session.userId).max || 0;

  db.prepare(`UPDATE tasks SET queue_position = ?, status = 'waiting' WHERE id = ?`)
    .run(maxPos + 1, req.params.id);

  recalculatePositions(req.session.userId);
  res.json({ success: true });
});

// ─── Slots Routes ─────────────────────────────────────────────────────────────

// Get available slots for a provider (public)
app.get('/api/slots/:username', (req, res) => {
  const provider = db.prepare('SELECT id FROM users WHERE username = ? AND role = ?')
    .get(req.params.username.toLowerCase(), 'provider');

  if (!provider) return res.status(404).json({ error: 'נותן שירות לא נמצא' });

  const today = new Date().toISOString().split('T')[0];
  const slots = db.prepare(`
    SELECT * FROM slots
    WHERE provider_id = ? AND is_booked = 0 AND date >= ?
    ORDER BY date ASC, time ASC
  `).all(provider.id, today);

  res.json(slots);
});

// Get all slots for provider (authenticated)
app.get('/api/slots', requireProvider, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  const slots = db.prepare(`
    SELECT s.*, t.requester_name, t.title as task_title
    FROM slots s
    LEFT JOIN tasks t ON s.task_id = t.id
    WHERE s.provider_id = ? AND s.date >= ?
    ORDER BY s.date ASC, s.time ASC
  `).all(req.session.userId, today);

  res.json(slots);
});

// Create slot(s)
app.post('/api/slots', requireProvider, (req, res) => {
  const { date, times, duration } = req.body;

  if (!date || !times || !times.length) {
    return res.status(400).json({ error: 'תאריך ושעות נדרשים' });
  }

  const insert = db.prepare(`
    INSERT INTO slots (provider_id, date, time, duration) VALUES (?, ?, ?, ?)
  `);

  const created = [];
  for (const time of times) {
    const result = insert.run(req.session.userId, date, time, duration || 30);
    created.push(result.lastInsertRowid);
  }

  res.json({ success: true, created });
});

// Delete slot
app.delete('/api/slots/:id', requireProvider, (req, res) => {
  const slot = db.prepare('SELECT * FROM slots WHERE id = ? AND provider_id = ?')
    .get(req.params.id, req.session.userId);

  if (!slot) return res.status(404).json({ error: 'סלוט לא נמצא' });
  if (slot.is_booked) return res.status(400).json({ error: 'לא ניתן למחוק סלוט שנקבע' });

  db.prepare('DELETE FROM slots WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── Public Queue Routes ──────────────────────────────────────────────────────

app.get('/api/queue/:username', (req, res) => {
  const provider = db.prepare(
    'SELECT id, name, username, service_type FROM users WHERE username = ? AND role = ?'
  ).get(req.params.username.toLowerCase(), 'provider');

  if (!provider) return res.status(404).json({ error: 'נותן שירות לא נמצא' });

  const waitingCount = db.prepare(`
    SELECT COUNT(*) as count FROM tasks
    WHERE provider_id = ? AND status IN ('waiting', 'in_progress')
  `).get(provider.id).count;

  res.json({ provider, waitingCount });
});

app.post('/api/queue/:username', (req, res) => {
  const { requester_name, title, description, slot_id } = req.body;

  if (!requester_name || !title) {
    return res.status(400).json({ error: 'שם וכותרת נדרשים' });
  }

  const provider = db.prepare(
    'SELECT id FROM users WHERE username = ? AND role = ?'
  ).get(req.params.username.toLowerCase(), 'provider');

  if (!provider) return res.status(404).json({ error: 'נותן שירות לא נמצא' });

  // Validate slot if provided
  if (slot_id) {
    const slot = db.prepare('SELECT * FROM slots WHERE id = ? AND provider_id = ? AND is_booked = 0')
      .get(slot_id, provider.id);
    if (!slot) return res.status(400).json({ error: 'הסלוט לא זמין' });
  }

  const maxPos = db.prepare(`
    SELECT MAX(queue_position) as max FROM tasks
    WHERE provider_id = ? AND status IN ('waiting', 'in_progress')
  `).get(provider.id).max || 0;

  const token = uuidv4();
  const requester_user_id = req.session.userId || null;

  const result = db.prepare(`
    INSERT INTO tasks (provider_id, requester_name, requester_user_id, title, description, status, queue_position, token, slot_id)
    VALUES (?, ?, ?, ?, ?, 'waiting', ?, ?, ?)
  `).run(provider.id, requester_name, requester_user_id, title, description || '', maxPos + 1, token, slot_id || null);

  // Mark slot as booked
  if (slot_id) {
    db.prepare('UPDATE slots SET is_booked = 1, task_id = ? WHERE id = ?')
      .run(result.lastInsertRowid, slot_id);
  }

  recalculatePositions(provider.id);

  const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(result.lastInsertRowid);
  const position = getPositionInQueue(task.id, provider.id);

  // Get slot info for calendar link
  let slotInfo = null;
  if (slot_id) {
    slotInfo = db.prepare('SELECT * FROM slots WHERE id = ?').get(slot_id);
  }

  res.json({
    success: true,
    token,
    taskId: result.lastInsertRowid,
    position,
    trackUrl: `/track.html?token=${token}`,
    slotInfo
  });
});

// ─── Track Route ──────────────────────────────────────────────────────────────

app.get('/api/track', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'טוקן נדרש' });

  const task = db.prepare('SELECT * FROM tasks WHERE token = ?').get(token);
  if (!task) return res.status(404).json({ error: 'בקשה לא נמצאה' });

  const provider = db.prepare('SELECT name, username, service_type FROM users WHERE id = ?').get(task.provider_id);
  const position = getPositionInQueue(task.id, task.provider_id);
  const peopleBefore = Math.max(0, position - 1);

  let slot = null;
  if (task.slot_id) {
    slot = db.prepare('SELECT * FROM slots WHERE id = ?').get(task.slot_id);
  }

  res.json({
    task: {
      id: task.id,
      title: task.title,
      description: task.description,
      status: task.status,
      requester_name: task.requester_name,
      created_at: task.created_at,
      started_at: task.started_at,
      done_at: task.done_at
    },
    provider,
    position,
    peopleBefore,
    slot
  });
});

// ─── Requester Dashboard ──────────────────────────────────────────────────────

app.get('/api/my-requests', requireAuth, (req, res) => {
  const tasks = db.prepare(`
    SELECT t.*, u.name as provider_name, u.username as provider_username, u.service_type as provider_service_type,
           s.date as slot_date, s.time as slot_time, s.duration as slot_duration
    FROM tasks t
    JOIN users u ON t.provider_id = u.id
    LEFT JOIN slots s ON t.slot_id = s.id
    WHERE t.requester_user_id = ?
    ORDER BY t.created_at DESC
  `).all(req.session.userId);

  const enriched = tasks.map(t => ({
    ...t,
    position: getPositionInQueue(t.id, t.provider_id),
    peopleBefore: Math.max(0, getPositionInQueue(t.id, t.provider_id) - 1)
  }));

  res.json(enriched);
});

// ─── Homepage widget data ─────────────────────────────────────────────────────

app.get('/api/dashboard-summary', requireAuth, (req, res) => {
  if (req.session.role === 'provider') {
    const waiting = db.prepare(`SELECT COUNT(*) as c FROM tasks WHERE provider_id = ? AND status = 'waiting'`).get(req.session.userId).c;
    const inProgress = db.prepare(`SELECT COUNT(*) as c FROM tasks WHERE provider_id = ? AND status = 'in_progress'`).get(req.session.userId).c;
    const doneToday = db.prepare(`SELECT COUNT(*) as c FROM tasks WHERE provider_id = ? AND status = 'done' AND date(done_at) = date('now')`).get(req.session.userId).c;
    const nextTask = db.prepare(`SELECT * FROM tasks WHERE provider_id = ? AND status = 'waiting' ORDER BY queue_position ASC LIMIT 1`).get(req.session.userId);

    res.json({ role: 'provider', waiting, inProgress, doneToday, nextTask });
  } else {
    const active = db.prepare(`SELECT COUNT(*) as c FROM tasks WHERE requester_user_id = ? AND status != 'done'`).get(req.session.userId).c;
    const myTasks = db.prepare(`
      SELECT t.*, u.name as provider_name, u.service_type
      FROM tasks t JOIN users u ON t.provider_id = u.id
      WHERE t.requester_user_id = ? AND t.status != 'done'
      ORDER BY t.created_at DESC LIMIT 3
    `).all(req.session.userId);

    const enriched = myTasks.map(t => ({
      ...t,
      position: getPositionInQueue(t.id, t.provider_id),
      peopleBefore: Math.max(0, getPositionInQueue(t.id, t.provider_id) - 1)
    }));

    res.json({ role: 'requester', active, tasks: enriched });
  }
});

// ─── Profile Routes ───────────────────────────────────────────────────────────

// Get full profile
app.get('/api/profile', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, username, role, service_type, created_at FROM users WHERE id = ?')
    .get(req.session.userId);
  if (!user) return res.status(404).json({ error: 'משתמש לא נמצא' });
  res.json(user);
});

// Update profile details
app.put('/api/profile', requireAuth, async (req, res) => {
  const { name, email, service_type } = req.body;

  if (!name || !email) {
    return res.status(400).json({ error: 'שם ואימייל נדרשים' });
  }

  try {
    db.prepare('UPDATE users SET name = ?, email = ?, service_type = ? WHERE id = ?')
      .run(name.trim(), email.toLowerCase().trim(), service_type || 'אחר', req.session.userId);

    req.session.name = name.trim();
    res.json({ success: true });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'האימייל הזה כבר בשימוש' });
    }
    res.status(500).json({ error: 'שגיאת שרת' });
  }
});

// Change password
app.put('/api/profile/password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'כל השדות נדרשים' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'הסיסמה חייבת להכיל לפחות 6 תווים' });
  }

  const user = db.prepare('SELECT password FROM users WHERE id = ?').get(req.session.userId);
  const match = await bcrypt.compare(currentPassword, user.password);
  if (!match) return res.status(401).json({ error: 'הסיסמה הנוכחית שגויה' });

  const hashed = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashed, req.session.userId);
  res.json({ success: true });
});

// Delete account
app.delete('/api/profile', requireAuth, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'נדרשת אימות סיסמה' });

  const user = db.prepare('SELECT password FROM users WHERE id = ?').get(req.session.userId);
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'סיסמה שגויה' });

  // Clean up user data
  db.prepare('DELETE FROM slots WHERE provider_id = ?').run(req.session.userId);
  db.prepare('UPDATE tasks SET requester_user_id = NULL WHERE requester_user_id = ?').run(req.session.userId);
  db.prepare('UPDATE tasks SET status = \'done\' WHERE provider_id = ? AND status != \'done\'').run(req.session.userId);
  db.prepare('DELETE FROM users WHERE id = ?').run(req.session.userId);

  req.session.destroy();
  res.json({ success: true });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function recalculatePositions(providerId) {
  const waiting = db.prepare(`
    SELECT id FROM tasks
    WHERE provider_id = ? AND status = 'waiting'
    ORDER BY queue_position ASC, created_at ASC
  `).all(providerId);

  const update = db.prepare('UPDATE tasks SET queue_position = ? WHERE id = ?');
  waiting.forEach((row, i) => update.run(i + 1, row.id));
}

function getPositionInQueue(taskId, providerId) {
  const task = db.prepare('SELECT status, queue_position FROM tasks WHERE id = ?').get(taskId);
  if (!task || task.status === 'done') return 0;
  if (task.status === 'in_progress') return 1;
  return task.queue_position;
}

// ─── Serve HTML pages ─────────────────────────────────────────────────────────

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Start server after DB is ready
initDb().then(database => {
  db = database;
  app.listen(PORT, () => {
    console.log(`TaskLine running at http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
