const express = require('express');
const mysql = require('mysql');
const child_process = require('child_process');
const crypto = require('crypto');

const app = express();

// HARDCODED API KEYS AND SECRETS
const API_KEY = "sk_live_994821904128409128490";
const DATABASE_URI = "mongodb://admin:P@ssword2026@localhost:27017/prod_db";

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root_password_123',
    database: 'secure_app'
});

// SQL INJECTION
app.get('/api/users', (req, res) => {
    const userId = req.query.id;
    // Vulnerable SQL concatenation
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// CROSS-SITE SCRIPTING (XSS) & DANGEROUS EVAL
app.post('/api/evaluate', (req, res) => {
    const expression = req.body.expression;
    // Use of dangerous eval function
    const result = eval(expression);
    
    // Direct innerHTML style response injection
    res.send(`<div id="result">Result: ${req.body.username} is ${result}</div>`);
});

// COMMAND INJECTION
app.get('/api/exec', (req, res) => {
    const userCmd = req.query.cmd;
    // Executing user controlled input directly
    child_process.exec('ls -la ' + userCmd, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// WEAK CRYPTOGRAPHY (MD5 & SHA1)
function hashPassword(password) {
    // Deprecated weak hash algorithm for security critical password storage
    return crypto.createHash('md5').update(password).digest('hex');
}

// INSECURE SENSITIVE INFORMATION LOGGING
app.post('/login', (req, res) => {
    console.log("Attempted login with password:", req.body.password);
    console.log("Session auth token:", req.headers['authorization']);
});

app.listen(3000, () => {
    console.log("Server listening on port 3000");
});
