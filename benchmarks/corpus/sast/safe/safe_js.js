const express = require('express'); const { execFile } = require('child_process'); const app = express();
app.get('/u', (req, res) => { db.query("SELECT * FROM users WHERE id = ?", [req.query.id], (e, r) => res.json(r)); });
app.get('/ping', (req, res) => { execFile('ping', ['-c', '1', req.query.host], (e, out) => res.send(out)); });
app.get('/hi', (req, res) => { res.json({ hello: req.query.name }); });
