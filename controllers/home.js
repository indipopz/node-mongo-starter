

/**
 * GET /index
 * Login page.
 */
exports.getIndex = (req, res) => {
    if(!req.user){
        return res.redirect('/auth/login');
    }
    return res.redirect('/home/dashboard');
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
        breadcrumbs: {'Dashboard' : '/home/dashboard', 'Overview': '#'}
    });
};