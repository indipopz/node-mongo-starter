


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