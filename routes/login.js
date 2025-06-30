// filepath: login-app/routes/login.js
var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt');
const session = require('express-session');
const { body, validationResult } = require('express-validator');

// Session configuration
router.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Input validation middleware
const validateLogin = [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
];

// Hardcoded credentials (for demo only - in production, use a database)
const USERNAME = 'admin';
const HASHED_PASSWORD = bcrypt.hashSync('admin', 10);

// GET login page
router.get('/', function(req, res, next) {
    res.render('login', { 
        title: 'Login',
        error: req.session.error || null
    });
    req.session.error = null;
});

// GET welcome page
router.get('/welcome', function(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.render('welcome', { title: 'Welcome', username: req.session.user });
});

// POST login
router.post('/', validateLogin, async function(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.session.error = errors.array()[0].msg;
        return res.redirect('/login');
    }

    const { username, password } = req.body;

    try {
        if (username === USERNAME && await bcrypt.compare(password, HASHED_PASSWORD)) {
            req.session.user = username;
            res.redirect('/login/welcome');
        } else {
            req.session.error = 'Invalid credentials';
            res.redirect('/login');
        }
    } catch (error) {
        next(error);
    }
});

module.exports = router;