const express = require('express');
const { greeting } = require('./render');

const app = express();

app.get('/hello', (req, res) => {
  // The query value is rendered into HTML by another module.
  res.send(greeting(req.query.name));
});

app.listen(3000);
