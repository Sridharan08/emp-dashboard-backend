const mongoose = require('mongoose');

const employeeSchema = new mongoose.Schema({
  employeeId: { type: String, default: () => `EMP-${Date.now()}` },
  name: String,
  address: String,
  age: Number,
  department: String,
  role: String,
  status: { type: String, enum: ['Remote Location', 'Contract Employee', 'Full-Time'] },
  coordinates: { lat: Number, lng: Number },
});

module.exports = mongoose.model('Employee', employeeSchema);