const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());
app.use(cors());

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

// Utility: hash password
async function hashData(data) {
  try {
    return await bcrypt.hash(data, 10);
  } catch (err) {
    console.log('Hashing error:', err);
  }
}

// Utility: compare password
async function compareHash(data, hash) {
  try {
    return await bcrypt.compare(data, hash);
  } catch (err) {
    console.log('Compare hash error:', err);
  }
}

// Get all users
app.get('/users', (req, res) => {
  connection.query('SELECT id, username, email FROM `user`', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Register user
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const hashedPassword = await hashData(password);

  connection.query(
    'INSERT INTO `user` (username, email, password) VALUES (?, ?, ?)',
    [username, email, hashedPassword],
    (err, results) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'Email already exists' });
        }
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'User registered successfully', userId: results.insertId });
    }
  );
});

// Login user
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  connection.query('SELECT * FROM `user` WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(400).json({ message: 'User not found' });

    const user = results[0];
    const match = await compareHash(password, user.password);
    if (!match) return res.status(400).json({ message: 'Incorrect password' });

    res.json({ message: 'Login successful', user: { id: user.id, username: user.username, email: user.email } });
  });
});

// Root
app.get('/', (req, res) => {
  res.send('API is working');
});

// Start server
app.listen(3000, () => {
  console.log('Server up and running on port 3000');
});
