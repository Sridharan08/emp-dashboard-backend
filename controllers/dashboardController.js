const Employee = require('../models/Employee');

exports.getStats = async (req, res) => {
  const countByStatus = await Employee.aggregate([
    { $group: { _id: '$status', count: { $sum: 1 } } },
  ]);
  const countByDept = await Employee.aggregate([
    { $group: { _id: '$department', count: { $sum: 1 } } },
  ]);
  res.json({ countByStatus, countByDept });
};