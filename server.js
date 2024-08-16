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
    port: 11283,
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
    const { name, mobile, email, username, password, 'confirm-password': confirmPassword } = req.body;

    // Check if password and confirm password match
    if (password !== confirmPassword) {
        return res.redirect('/signup.html?passwordError=Passwords do not match.');
    }

    // Check for existing email, mobile, or username
    const checkSql = 'SELECT * FROM users WHERE email = ? OR mobile = ? OR username = ?';
    db.query(checkSql, [email, mobile, username], (err, results) => {
        if (err) return res.redirect('/signup.html?formMessage=Error checking for existing users.');

        let errors = {};
        if (results.some(row => row.email === email)) {
            errors.emailError = 'Email already exists.';
        }
        if (results.some(row => row.mobile === mobile)) {
            errors.mobileError = 'Mobile number already exists.';
        }
        if (results.some(row => row.username === username)) {
            errors.usernameError = 'Username already exists.';
        }

        if (Object.keys(errors).length > 0) {
            return res.redirect('/signup.html?' + new URLSearchParams(errors).toString());
        }

        // Proceed with user registration
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) return res.redirect('/signup.html?formMessage=Error hashing password.');

            const sql = 'INSERT INTO users (name, mobile, email, username, password) VALUES (?, ?, ?, ?, ?)';
            db.query(sql, [name, mobile, email, username, hashedPassword], (err, result) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.redirect('/signup.html?formMessage=Error registering user. Duplicate entry.');
                    }
                    return res.redirect('/signup.html?formMessage=Error registering user.');
                }
                res.redirect('/signup.html?formMessage=User registered successfully.');
            });
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], (err, results) => {
        if (err) return res.status(500).send('Error retrieving user.');
        if (results.length > 0) {
            bcrypt.compare(password, results[0].password, (err, isMatch) => {
                if (err) return res.status(500).send('Error comparing passwords.');
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
        if (err) return res.status(500).send('Error retrieving users.');
        res.json(results);
    });
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
