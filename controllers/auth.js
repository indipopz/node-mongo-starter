const { promisify } = require('util');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const User = require('../models/User');

const randomBytesAsync = promisify(crypto.randomBytes);


/**
 * GET /login
 * Login page.
 */
exports.getLogin = (req, res) => {
    if (req.user) {
        return res.redirect('/');
    }
    res.render('account/login', {
        title: 'Login'
    });
};


/**
 * GET /Register
 * Register page.
 */
exports.getRegister = (req, res) => {
    if (req.user) {
        return res.redirect('/');
    }
    res.render('account/register', {
        title: 'Register'
    });
};

/**
 * POST /Register
 * Register page.
 */
exports.postRegister = (req, res, next) => {
    // req.assert('email', 'Email is not valid').isEmail();
    // req.assert('password', 'Password must be at least 4 characters long').len(4);
    // req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);
    // req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

    const errors = req.validationErrors();
    if (errors) {
        req.flash('errors', errors);
        return res.redirect('/register');
    }

    // noinspection JSAnnotator
    const user = new User({
        email: req.body.email,
        password: req.body.password,
        profile: {
            firstName: req.body.firstName,
            lastName: req.body.lastName
        }
    });

    User.findOne({ email: req.body.email }, (err, existingUser) => {
        if (err) { return next(err); }
        if (existingUser) {
            req.flash('errors', { msg: 'Account with that email address already exists.' });
            return res.redirect('/register');
        }
        user.save((err) => {
            if (err) { return next(err); }
            req.logIn(user, (err) => {
                if (err) {
                    return next(err);
                }
                res.redirect('/');
            });
        });
    });
};

/**
 * GET /Forgot Password
 * Forgot Password page.
 */
exports.forgotPassword = (req, res) => {
    if (req.user) {
        return res.redirect('/');
    }
    res.render('account/forgot-password', {
        title: 'Forgot Password'
    });
};