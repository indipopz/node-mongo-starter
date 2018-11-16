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
    req.assert('email', 'Email is not valid').isEmail();
    req.assert('password', 'Password cannot be blank').notEmpty();
    req.assert('password', 'Password must be 5 characters long').isLength({min: 5});
    req.assert('confirmPassword', 'Confirm Password must be equal to password').equals(req.body.password);
    req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

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
 * GET /logout
 * Log out.
 */
exports.logout = (req, res) => {
    req.logout();
    req.session.destroy((err) => {
        if (err) console.log('Error : Failed to destroy the session during logout.', err);
        req.user = null;
        res.redirect('/');
    });
};


/**
 * GET /Forgot Password
 * Forgot Password page.
 */
exports.getForgotPassword = (req, res) => {
    if (req.user) {
        return res.redirect('/');
    }
    res.render('account/forgot-password', {
        title: 'Forgot Password'
    });
};

/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */
exports.postForgotPassword = (req, res, next) => {
    req.assert('email', 'Please enter a valid email address.').isEmail();
    req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

    const errors = req.validationErrors();

    if (errors) {
        req.flash('errors', errors);
        return res.redirect('/forgot-password');
    }

    const createRandomToken = randomBytesAsync(16)
        .then(buf => buf.toString('hex'));

    const setRandomToken = token =>
        User
            .findOne({ email: req.body.email })
            .then((user) => {
                if (!user) {
                    req.flash('errors', { msg: 'Account with that email address does not exist.' });
                } else {
                    user.passwordResetToken = token;
                    user.passwordResetExpires = Date.now() + 3600000; // 1 hour
                    user = user.save();
                }
                return user;
            });

    const sendForgotPasswordEmail = (user) => {
        if (!user) { return; }
        const token = user.passwordResetToken;
        let transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_PASSWORD
            }
        });
        const mailOptions = {
            to: user.email,
            from: 'admin@nodemongostarter.com',
            subject: 'Reset your password on Node Mongo Starter',
            text: `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n
        Please click on the following link, or paste this into your browser to complete the process:\n\n
        http://${req.headers.host}/reset-password/${token}\n\n
        If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };
        return transporter.sendMail(mailOptions)
            .then(() => {
                req.flash('info', { msg: `An e-mail has been sent to ${user.email} with further instructions.` });
            })
            .catch((err) => {
                if (err.message === 'self signed certificate in certificate chain') {
                    console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
                    transporter = nodemailer.createTransport({
                        service: 'Gmail',
                        auth: {
                            user: process.env.GMAIL_USER,
                            pass: process.env.GMAIL_PASSWORD
                        },
                        tls: {
                            rejectUnauthorized: false
                        }
                    });
                    return transporter.sendMail(mailOptions)
                        .then(() => {
                            req.flash('info', { msg: `An e-mail has been sent to ${user.email} with further instructions.` });
                        });
                }
                console.log('ERROR: Could not send forgot password email after security downgrade.\n', err);
                req.flash('errors', { msg: 'Error sending the password reset message. Please try again shortly.' });
                return err;
            });
    };

    createRandomToken
        .then(setRandomToken)
        .then(sendForgotPasswordEmail)
        .then(() => res.redirect('/forgot-password'))
        .catch(next);
};

/**
 * GET /reset/:token
 * Reset Password page.
 */
exports.getResetPassword = (req, res, next) => {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    User
        .findOne({ passwordResetToken: req.params.token })
        .where('passwordResetExpires').gt(Date.now())
        .exec((err, user) => {
            if (err) { return next(err); }
            if (!user) {
                req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
                return res.redirect('/forgot-password');
            }
            res.render('account/reset-password', {
                title: 'Reset Password'
            });
        });
};

/**
 * POST /reset/:token
 * Process the reset password request.
 */
exports.postResetPassword = (req, res, next) => {
    req.assert('newPassword', 'New Password must be at least 4 characters long.').len(4);
    req.assert('confirmNewPassword', 'Confirm New Passwords must match New Password').equals(req.body.newPassword);

    const errors = req.validationErrors();

    if (errors) {
        req.flash('errors', errors);
        return res.redirect('back');
    }

    const resetPassword = () =>
        User
            .findOne({ passwordResetToken: req.params.token })
            .where('passwordResetExpires').gt(Date.now())
            .then((user) => {
                if (!user) {
                    req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
                    return res.redirect('back');
                }
                user.password = req.body.newPassword;
                user.passwordResetToken = undefined;
                user.passwordResetExpires = undefined;
                return user.save().then(() => new Promise((resolve, reject) => {
                    req.logIn(user, (err) => {
                        if (err) { return reject(err); }
                        resolve(user);
                    });
                }));
            });

    const sendResetPasswordEmail = (user) => {
        if (!user) { return; }
        let transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_PASSWORD
            }
        });
        const mailOptions = {
            to: user.email,
            from: 'admin@nodemongostarter.com',
            subject: 'Your Node Mongo Starter password has been changed',
            text: `Hello,\n\nThis is a confirmation that the password for your account ${user.email} has just been changed.\n`
        };
        return transporter.sendMail(mailOptions)
            .then(() => {
                req.flash('success', { msg: 'Success! Your password has been changed.' });
            })
            .catch((err) => {
                if (err.message === 'self signed certificate in certificate chain') {
                    console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
                    transporter = nodemailer.createTransport({
                        service: 'Gmail',
                        auth: {
                            user: process.env.GMAIL_USER,
                            pass: process.env.GMAIL_PASSWORD
                        },
                        tls: {
                            rejectUnauthorized: false
                        }
                    });
                    return transporter.sendMail(mailOptions)
                        .then(() => {
                            req.flash('success', { msg: 'Success! Your password has been changed.' });
                        });
                }
                console.log('ERROR: Could not send password reset confirmation email after security downgrade.\n', err);
                req.flash('warning', { msg: 'Your password has been changed, however we were unable to send you a confirmation email. We will be looking into it shortly.' });
                return err;
            });
    };

    resetPassword()
        .then(sendResetPasswordEmail)
        .then(() => { if (!res.finished) res.redirect('/'); })
        .catch(err => next(err));
};

/**
 * GET /Register
 * Register page.
 */
exports.getChangePassword = (req, res) => {
    if (!req.user) {
        return res.redirect('/login');
    }
    res.render('account/change-password', {
        title: 'Change Password'
    });
};

/**
 * POST /change-password
 * Process the reset password request.
 */
exports.postChangePassword = (req, res, next) => {
    req.assert('currentPassword', 'Current password cannot be blank').notEmpty();
    req.assert('newPassword', 'New Password must be at least 4 characters long.').len(4);
    req.assert('confirmNewPassword', 'Confirm New Passwords must match New Password').equals(req.body.newPassword);

    const errors = req.validationErrors();

    if (errors) {
        req.flash('errors', errors);
        return res.redirect('back');
    }

    const changePassword = () =>
        User
            .findOne({ _id: req.user._id })
            .then((user) => {
                if (!user) {
                    req.flash('errors', { msg: 'User not found.' });
                    return res.redirect('back');
                }
                user.comparePassword(req.body.currentPassword, (err, isMatch) => {
                   if(err){
                       req.flash('errors', { msg: 'User not found.' });
                       return res.redirect('back');
                   }
                   if(!isMatch){
                       req.flash('errors', { msg: 'Current password is wrong.' });
                       return res.redirect('back');
                   }
                });
                user.password = req.body.newPassword;
                return user.save().then(() => new Promise((resolve, reject) => {
                    req.logIn(user, (err) => {
                        if (err) { return reject(err); }
                        resolve(user);
                    });
                }));
            });

    const sendResetPasswordEmail = (user) => {
        if (!user) { return; }
        let transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_PASSWORD
            }
        });
        const mailOptions = {
            to: user.email,
            from: 'admin@nodemongostarter.com',
            subject: 'Your Node Mongo Starter password has been changed',
            text: `Hello,\n\nThis is a confirmation that the password for your account ${user.email} has just been changed.\n`
        };
        return transporter.sendMail(mailOptions)
            .then(() => {
                req.flash('success', { msg: 'Success! Your password has been changed.' });
            })
            .catch((err) => {
                if (err.message === 'self signed certificate in certificate chain') {
                    console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
                    transporter = nodemailer.createTransport({
                        service: 'Gmail',
                        auth: {
                            user: process.env.GMAIL_USER,
                            pass: process.env.GMAIL_PASSWORD
                        },
                        tls: {
                            rejectUnauthorized: false
                        }
                    });
                    return transporter.sendMail(mailOptions)
                        .then(() => {
                            req.flash('success', { msg: 'Success! Your password has been changed.' });
                        });
                }
                console.log('ERROR: Could not send password reset confirmation email after security downgrade.\n', err);
                req.flash('warning', { msg: 'Your password has been changed, however we were unable to send you a confirmation email. We will be looking into it shortly.' });
                return err;
            });
    };

    changePassword()
        .then(sendResetPasswordEmail)
        .then(() => { if (!res.finished) res.redirect('/'); })
        .catch(err => next(err));
};