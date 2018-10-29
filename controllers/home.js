

/**
 * GET /index
 * Login page.
 */
exports.getIndex = (req, res) => {
    if(!req.user){
        return res.redirect('/login')
    }
    res.render('home/index', {
        title: 'index'
    });
};