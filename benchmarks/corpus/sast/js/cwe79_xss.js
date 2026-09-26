const express = require('express'); const app = express();
app.get('/hi', (req, res) => { res.send('<h1>Hello ' + req.query.name + '</h1>'); });
