const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

// JWT Secret
const JWT_SECRET = 'your_super_secret_key';
const JWT_EXPIRES_IN = '1h';

// MySQL connection
const connection = mysql.createConnection({
  host: '185.196.75.153',
  user: 'admin',
  database: 'mydb',
  password: 'admin'
});

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err.message);
    process.exit(1);
  }
  console.log('Connected to MySQL database');
});

// Utility functions
async function hashData(data) {
  return await bcrypt.hash(data, 10);
}

async function compareHash(data, hash) {
  return await bcrypt.compare(data, hash);
}

function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Routes

// Root
app.get('/', (req, res) => res.send('API is working'));

// Register
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ message: 'All fields are required' });

  const hashedPassword = await hashData(password);

  connection.query(
    'INSERT INTO `user` (username, email, password) VALUES (?, ?, ?)',
    [username, email, hashedPassword],
    (err, results) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ message: 'Email already exists' });
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'User registered successfully', userId: results.insertId });
    }
  );
});

// Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

  connection.query('SELECT * FROM `user` WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(400).json({ message: 'User not found' });

    const user = results[0];
    const match = await compareHash(password, user.password);
    if (!match) return res.status(400).json({ message: 'Incorrect password' });

    const token = generateToken(user);
    res.json({ message: 'Login successful', token });
  });
});

// Protected route: Get all users
app.get('/users', authenticateToken, (req, res) => {
  connection.query('SELECT id, username, email FROM `user`', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Server
app.listen(3000, () => console.log('Server running on port 3000'));
