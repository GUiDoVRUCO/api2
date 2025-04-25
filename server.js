require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('users.db', (err) => {
  if (err) {
    console.error('Erro ao conectar ao banco:', err.message);
    process.exit(1);
  }
  console.log('Conectado ao banco SQLite.');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    canInstall BOOLEAN DEFAULT 0,
    createdAt TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  const defaultAdmin = { username: 'gui12', password: process.env.ADMIN_PASSWORD };
  bcrypt.hash(defaultAdmin.password, 10, (err, hash) => {
    if (err) return console.error('Erro ao criar admin:', err);
    db.run(
      `INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)`,
      [defaultAdmin.username, hash],
      (err) => {
        if (err) console.error('Erro ao inserir admin:', err);
      }
    );
  });
});

const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = decoded;
    next();
  });
};

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM admins WHERE username = ?`, [username], async (err, admin) => {
    if (err || !admin) return res.status(401).json({ error: 'Credenciais inválidas' });

    const isValid = await bcrypt.compare(password, admin.password);
    if (!isValid) return res.status(401).json({ error: 'Credenciais inválidas' });

    const token = jwt.sign({ username: admin.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  });
});

app.post('/api/users', authenticate, (req, res) => {
  const { username, canInstall } = req.body;
  db.run(
    `INSERT INTO users (username, canInstall, createdAt) VALUES (?, ?, ?)`,
    [username, canInstall ? 1 : 0, new Date().toISOString()],
    function (err) {
      if (err) return res.status(400).json({ error: 'Erro ao adicionar usuário' });
      res.json({ id: this.lastID, username, canInstall });
    }
  );
});

app.get('/api/users', authenticate, (req, res) => {
  db.all(`SELECT id, username, canInstall, createdAt FROM users`, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Erro ao listar usuários' });
    res.json(rows);
  });
});

app.put('/api/users/:id', authenticate, (req, res) => {
  const { canInstall } = req.body;
  db.run(
    `UPDATE users SET canInstall = ? WHERE id = ?`,
    [canInstall ? 1 : 0, req.params.id],
    function (err) {
      if (err || this.changes === 0) return res.status(400).json({ error: 'Erro ao atualizar usuário' });
      res.json({ message: 'Permissão atualizada' });
    }
  );
});

app.delete('/api/users/:id', authenticate, (req, res) => {
  db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], function (err) {
    if (err || this.changes === 0) return res.status(400).json({ error: 'Erro ao deletar usuário' });
    res.json({ message: 'Usuário deletado' });
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

process.on('SIGINT', () => {
  db.close((err) => {
    if (err) console.error('Erro ao fechar banco:', err);
    console.log('Banco fechado.');
    process.exit(0);
  });
});
