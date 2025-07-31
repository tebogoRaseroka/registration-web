const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Database setup
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) console.error(err);
    else console.log('Connected to SQLite database.');
});

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT
)`);

// Signup route
app.post('/signup', (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    db.run(`INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
        [name, email, hashedPassword],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ message: 'Email already registered.' });
                }
                return res.status(500).json({ message: 'Database error.' });
            }
            res.status(200).json({ message: 'User registered successfully.' });
        }
    );
});

// Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) return res.status(500).json({ message: 'Database error.' });
        if (!user) return res.status(400).json({ message: 'User not found.' });

        const isMatch = bcrypt.compareSync(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Incorrect password.' });
        }
        res.status(200).json({ message: 'Login successful.' });
    });
});

// Start server
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
