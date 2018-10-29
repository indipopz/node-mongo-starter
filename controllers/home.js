

/**
 * GET /index
 * Login page.
 */
exports.getIndex = (req, res) => {
	console.log(req.user);
    if (req.user) {
        return res.redirect('/');
    }
    res.render('home/index', {
        title: 'index'
    });
};