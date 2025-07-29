const mongoose = require('mongoose');

const auditSchema = new mongoose.Schema({
  employeeId: String,
  oldData: Object,
  newData: Object,
  changedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Audit', auditSchema);