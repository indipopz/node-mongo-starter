const router = require('express').Router();
const homeController = require('./../controllers/home');

router.get('/', homeController.getIndex);
router.get('/dashboard', homeController.getDashboard);

module.exports = router;


