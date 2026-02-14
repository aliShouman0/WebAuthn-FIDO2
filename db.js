const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Create/open database file
const dbPath = path.join(__dirname, 'webauthn.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
  }
});

// Enable foreign keys
db.run('PRAGMA foreign_keys = ON');

// Create tables
db.serialize(() => {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) console.error('Error creating users table:', err);
    else console.log('✓ Users table ready');
  });

  // Credentials table (stores registered passkeys)
  db.run(`
    CREATE TABLE IF NOT EXISTS credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      credentialID TEXT UNIQUE NOT NULL,
      publicKey BLOB NOT NULL,
      counter INTEGER DEFAULT 0,
      transports TEXT,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `, (err) => {
    if (err) console.error('Error creating credentials table:', err);
    else console.log('✓ Credentials table ready');
  });

  // Challenges table (for registration & login, single-use)
  db.run(`
    CREATE TABLE IF NOT EXISTS challenges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      challenge TEXT UNIQUE NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('registration', 'authentication')),
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expiresAt TIMESTAMP NOT NULL,
      FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `, (err) => {
    if (err) console.error('Error creating challenges table:', err);
    else console.log('✓ Challenges table ready');
  });
});

module.exports = db; 