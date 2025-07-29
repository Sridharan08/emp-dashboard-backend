const express = require('express');
const { createEmployee, updateEmployee, getEmployees, getEmployeeAudit, deleteEmployee } = require('../controllers/employeeController');
//const auth = require('../middlewares/auth');
const router = express.Router();

router.get('/',  getEmployees);
router.post('/',  createEmployee);
router.put('/:id',  updateEmployee);
router.delete('/:id', deleteEmployee)
router.get('/:id/audit',  getEmployeeAudit);

module.exports = router;