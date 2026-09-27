const express = require('express'); const app = express();
app.get('/calc', (req, res) => { res.send(String(eval(req.query.expr))); });
