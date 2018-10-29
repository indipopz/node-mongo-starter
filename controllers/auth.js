const { promisify } = require('util');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const { check, validationResult, body } = require('express-validator/check');
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
 * POST /login
 * Sign in using email and password.
 */
exports.postLogin = (req, res, next) => {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password cannot be blank').notEmpty();
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/login');
  }

  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) {
      req.flash('errors', info);
      return res.redirect('/login');
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      req.flash('success', { msg: 'Success! You are logged in.' });
      res.redirect(req.session.returnTo || '/');
    });
  })(req, res, next);
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
    const errors = validationResult(req);
    console.log(errors.array());
    if (!errors.isEmpty()) {
        req.flash('errors', errors.array());
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
            req.flash('success', { msg: 'Congratulation !! You have been successfully registered.' });
            return res.redirect('/login');
        });
    });
};

exports.validate = (method, req) => {
    console.log(req);
    switch (method) {
        case 'registerUser': {
            return [
                check('email').isEmail().withMessage('Please enter a valid email.'),
                check('password').isLength({ min: 5 }).withMessage('Password must be 5 characters long')
            ];
        }
    }
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