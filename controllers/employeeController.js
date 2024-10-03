const Employee = require('../models/employeeModel');

// Create new Employee
const createEmployee = async (req, res) => {
  try {
    const newEmployee = new Employee({
      ...req.body,
      employeeId: generateEmployeeId(),
    });
    await newEmployee.save();
    res.status(201).json(newEmployee);
  } catch (err) {
    res.status(500).json({ message: 'Error creating employee', error: err });
  }
};

// Update Employee and store historical data
const updateEmployee = async (req, res) => {
  const { employeeId } = req.params; // Get the employeeId from the request params
  const updateData = req.body; // The data to update

  try {
    // Fetch the existing employee data
    const existingEmployee = await Employee.findOne({ employeeId });

    if (!existingEmployee) {
      return res.status(404).json({ message: 'Employee not found' });
    }

    // Prepare the audit data
    const auditEntry = {
      modifiedAt: new Date(),
      oldData: existingEmployee.toObject(), // Store the old data
      newData: { ...existingEmployee.toObject(), ...updateData }, // Combine old data with new updates
    };

    // Update the employee without modifying the auditTrail
    const updatedEmployee = await Employee.findOneAndUpdate(
      { employeeId },
      updateData,
      { new: true, runValidators: true } // Return the updated document and validate
    );

    // Now, push the audit entry into the auditTrail array
    await Employee.findOneAndUpdate(
      { employeeId },
      { $push: { auditTrail: auditEntry } }, // Add the audit entry to the auditTrail array
      { new: true } // Not necessary to return, but can be useful for confirmation
    );

    console.log('Updated Employee:', updatedEmployee); // Log the updated employee data to the console

    res.status(200).json(updatedEmployee); // Respond with the updated employee data
  } catch (error) {
    console.error('Error updating employee:', error); // Log the error for debugging
    res.status(500).json({ message: 'Error updating employee', error: error.message }); // Include error message
  }
};


// Fetch all Employees
const getEmployees = async (req, res) => {
  try {
    const employees = await Employee.find();
    res.json(employees);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching employees', error: err });
  }
};

// Utility function to generate Employee ID
const generateEmployeeId = () => {
  return `EMP${Math.floor(Math.random() * 10000)}`; // Generates a random employee ID
};

module.exports = {
  createEmployee,
  updateEmployee,
  getEmployees,
};