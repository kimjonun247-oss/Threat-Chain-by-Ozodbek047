const express = require('express'); const mysql = require('mysql');
const app = express(); const db = mysql.createConnection({});
app.get('/u', (req, res) => { db.query("SELECT * FROM users WHERE id = " + req.query.id, (e, r) => res.json(r)); });
