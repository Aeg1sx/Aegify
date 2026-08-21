const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();
const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });

// SQL Injection
app.get('/users', (req, res) => {
    const id = req.query.id;
    db.query("SELECT * FROM users WHERE id = " + id, (err, rows) => {
        res.json(rows);
    });
});

// Command Injection
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec("ping -c 1 " + host, (err, stdout) => {
        res.send(stdout);
    });
});

// XSS via innerHTML (pattern-based)
app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send(`<div id="output"></div><script>document.getElementById('output').innerHTML = '${name}'</script>`);
});

// Path Traversal
app.get('/file', (req, res) => {
    const filename = req.query.file;
    fs.readFile('/data/' + filename, 'utf-8', (err, data) => {
        res.send(data);
    });
});

function validateInput(data) {
    if (!data) throw new Error('empty');
    return data.trim();
}

function queryUser(id) {
    return db.query("SELECT * FROM users WHERE id = " + id);
}

app.get('/users2', (req, res) => {
    const id = validateInput(req.query.id);
    const result = queryUser(id);
    res.json(result);
});

app.listen(3000);
