const Employee = require('../models/Employee');
const Audit = require('../models/Audit');

exports.createEmployee = async (req, res) => {
  const newEmp = await Employee.create(req.body);
  res.json(newEmp);
};

exports.updateEmployee = async (req, res) => {
  const { id } = req.params;
  const oldData = await Employee.findById(id);
  const updated = await Employee.findByIdAndUpdate(id, req.body, { new: true });
  await Audit.create({ employeeId: id, oldData, newData: updated });
  res.json(updated);
};

exports.getEmployees = async (req, res) => {
  const employees = await Employee.find();
  res.json(employees);
};

exports.getEmployeeAudit = async (req, res) => {
  const { id } = req.params;
  const audits = await Audit.find({ employeeId: id });
  res.json(audits);
};
exports.deleteEmployee = async (req, res) => {
  const { id } = req.params;
  await Employee.findByIdAndDelete(id);
  res.json({ message: 'Employee deleted' });
};