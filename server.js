const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = 11283;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

const db = mysql.createConnection({
    host: 'mysql-1685e106-dhanushkumar558-b8b4.i.aivencloud.com',
    port: 11283, // Ensure the port is correct
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'defaultdb'
});



db.connect((err) => {
    if (err) throw err;
    console.log('Connected to database.');
});

// Redirect root URL to the sign-up page
app.get('/', (req, res) => {
    res.redirect('/signup.html');
});

app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) throw err;
        const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';
        db.query(sql, [username, hashedPassword], (err, result) => {
            if (err) throw err;
            res.send('User registered.');
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            bcrypt.compare(password, results[0].password, (err, isMatch) => {
                if (err) throw err;
                if (isMatch) {
                    res.send('Login successful.');
                } else {
                    res.send('Invalid credentials.');
                }
            });
        } else {
            res.send('No user found.');
        }
    });
});

app.get('/get', (req, res) => {
    const sql = 'SELECT * FROM users';
    db.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
