/**
 * SQLite wrapper using sql.js (pure JavaScript, no native compilation).
 * Provides a better-sqlite3-compatible synchronous API.
 * Data is persisted to disk after every write operation.
 */

const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '../database/taskline.db');

let sqlDb = null;

// ─── Compatibility wrapper ────────────────────────────────────────────────────

class Statement {
  constructor(db, sql) {
    this._db = db;
    this._sql = sql;
  }

  run(...args) {
    const params = flatArgs(args);
    this._db.run(this._sql, params);
    const lastId = this._db.exec('SELECT last_insert_rowid() as id')[0]?.values[0][0] ?? null;
    const changes = this._db.getRowsModified();
    save();
    return { lastInsertRowid: lastId, changes };
  }

  get(...args) {
    const params = flatArgs(args);
    const stmt = this._db.prepare(this._sql);
    stmt.bind(params);
    let row;
    if (stmt.step()) {
      row = stmt.getAsObject();
    }
    stmt.free();
    return row;
  }

  all(...args) {
    const params = flatArgs(args);
    const stmt = this._db.prepare(this._sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) {
      rows.push(stmt.getAsObject());
    }
    stmt.free();
    return rows;
  }
}

class Transaction {
  constructor(fn) {
    this._fn = fn;
  }
  run(args) {
    sqlDb.run('BEGIN');
    try {
      this._fn(args);
      sqlDb.run('COMMIT');
    } catch(e) {
      sqlDb.run('ROLLBACK');
      throw e;
    }
    save();
  }
}

class DB {
  prepare(sql) {
    return new Statement(sqlDb, sql);
  }

  exec(sql) {
    sqlDb.run(sql);
    save();
  }

  pragma() {} // no-op for compatibility

  transaction(fn) {
    return new Transaction(fn);
  }
}

function flatArgs(args) {
  if (args.length === 1 && Array.isArray(args[0])) return args[0];
  return args;
}

function save() {
  const data = sqlDb.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// ─── Initialization ───────────────────────────────────────────────────────────

async function init() {
  const initSqlJs = require('sql.js');
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    sqlDb = new SQL.Database(fileBuffer);
  } else {
    sqlDb = new SQL.Database();
  }

  sqlDb.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      service_type TEXT DEFAULT 'אחר',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Add service_type column if upgrading from older DB
  try { sqlDb.run(`ALTER TABLE users ADD COLUMN service_type TEXT DEFAULT 'אחר'`); } catch(e) {}

  sqlDb.run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider_id INTEGER NOT NULL,
      requester_name TEXT NOT NULL,
      requester_user_id INTEGER,
      title TEXT NOT NULL,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'waiting',
      queue_position INTEGER,
      token TEXT UNIQUE,
      slot_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      started_at DATETIME,
      done_at DATETIME
    )
  `);

  // Add slot_id column if upgrading
  try { sqlDb.run(`ALTER TABLE tasks ADD COLUMN slot_id INTEGER`); } catch(e) {}

  sqlDb.run(`
    CREATE TABLE IF NOT EXISTS slots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      duration INTEGER DEFAULT 30,
      is_booked INTEGER DEFAULT 0,
      task_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  save();
  return new DB();
}

module.exports = { init };
