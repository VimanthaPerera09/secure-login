const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const cors = require('cors')

const app = express();
const port = 3001;

app.use(cors());
app.options('*', cors()); 
app.use(bodyParser.json());

// Database connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'myapp_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Middleware for handling SQL injection prevention
const sanitizeMiddleware = (req, res, next) => {
  // Implement your SQL injection prevention logic here
  // For simplicity, you can use parameterized queries with prepared statements
  next();
};

app.use(sanitizeMiddleware);

// Route to authenticate users
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, hashedPassword]);
    if (rows.length === 1) {
      res.json({ success: true, role: rows[0].role });
    } else {
      res.json({ success: false });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

// Route to get customer details based on user role
app.get('/customer-details', async (req, res) => {
  const { role } = req.query;

  try {
    let query = 'SELECT name, email, address';
    if (role === 'admin') {
      query += ', credit_card';
    }
    if (role === 'privileged') {
      query += ', medical_expenses';
    }
    query += ' FROM customers';

    const [rows] = await pool.query(query);
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

// Route to add new users
app.post('/add-user', async (req, res) => {
  const { username, password, role } = req.body;

  try {
    // Check if the user already exists
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);

    if (existingUsers.length > 0) {
      res.json({ success: false, error: 'User already exists' });
      return;
    }

    // Hash the password before storing it in the database
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    // Insert the new user into the database
    await pool.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role]);

    res.json({ success: true, message: 'User added successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
