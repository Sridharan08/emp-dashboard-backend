const express = require('express');
const { createEmployee, updateEmployee, getEmployees } = require('../controllers/employeeController');
const router = express.Router();

router.post('/create', createEmployee);
router.put('/:employeeId', updateEmployee);
router.get('/', getEmployees);

module.exports = router;