// filepath: login-app/routes/index.js
var express = require('express');
var router = express.Router();

// GET home page
router.get('/', function(req, res, next) {
  res.redirect('/login');
});

// Export the router
module.exports = router;