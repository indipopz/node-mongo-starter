const router = require('express').Router();
const passport = require('passport');
const authController = require('./../controllers/auth');

// App login
router.get('/login', authController.getLogin);
router.post('/login', authController.postLogin);

router.get('/register', authController.getRegister);
router.post('/register', authController.postRegister);

router.get('/logout', authController.logout);

router.get('/forgot-password', authController.getForgotPassword);
router.post('/forgot-password', authController.postForgotPassword);

router.get('/reset-password/:token', authController.getResetPassword);
router.post('/reset-password/:token', authController.postResetPassword);

router.get('/change-password/', authController.getChangePassword);
router.post('/change-password/', authController.postChangePassword);

router.get('/google', passport.authenticate('google', { scope: 'profile email' }));
router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/auth/login' }), (req, res) => {
    res.redirect(req.session.returnTo || '/home/dashboard');
});


module.exports = router;




