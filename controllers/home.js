

/**
 * GET /index
 * Login page.
 */
exports.getIndex = (req, res) => {
    if(!req.user){
        return res.redirect('/auth/login')
    }
    res.render('home/index', {
        title: 'index'
    });
};



/**
 * GET /dashboard
 * Dashboard page.
 */
exports.getDashboard = (req, res) => {
    if(!req.user){
        return res.redirect('/auth/login')
    }
    res.render('home/dashboard', {
        title: 'Dashboard',
        breadcrumbs: {'Dashboard' : '/dashboard', 'Overview': '#'}
    });
};