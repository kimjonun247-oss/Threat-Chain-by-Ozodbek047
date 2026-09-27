const express = require('express'); const fs = require('fs'); const app = express();
app.get('/dl', (req, res) => { res.send(fs.readFileSync('/data/' + req.query.f)); });
