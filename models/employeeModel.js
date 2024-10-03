const mongoose = require('mongoose');

const employeeSchema = new mongoose.Schema({
  employeeId: { type: String, unique: true },
  name: { type: String, required: true },
  address: { type: String, required: true },
  age: { type: Number, required: true },
  department: { type: String, required: true },
  status: { type: String, enum: ['Remote Location', 'Contract Employee', 'Full-Time'], required: true },
  location: {
    coordinates: { type: [Number], required: true }, // Longitude, Latitude
  },
  auditTrail: [
    {
      modifiedAt: { type: Date, default: Date.now },
      oldData: { type: Object },
      newData: { type: Object },
    },
  ]
});

const Employee = mongoose.model('Employee', employeeSchema);
module.exports = Employee;