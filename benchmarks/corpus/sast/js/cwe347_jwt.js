const jwt = require('jsonwebtoken');
module.exports = (token) => jwt.verify(token, 'secret', { algorithms: ['none', 'HS256'] });
