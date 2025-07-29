const express = require('express');
const { getStats } = require('../controllers/dashboardController');
//const auth = require('../middlewares/auth');
const router = express.Router();

router.get('/',  getStats);

module.exports = router;