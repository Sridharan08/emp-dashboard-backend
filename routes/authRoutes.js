const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/User');
const sendEmail = require('../utils/sendEmail');
const  { getAccountInfo,
  changePassword,
  deleteAccount
} = require('../controllers/authController');
const { protect } = require('../middlewares/auth');


const router = express.Router();

// Generate JWT
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
};

// ------------------ SIGNUP ------------------
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const userExists = await User.findOne({ email });

    if (userExists) {
      return res.status(400).json({ msg: 'Admin already exists' });
    }

    const user = new User({ name, email, password }); // ⬅ No need to hash here
    await user.save(); // ⬅ This triggers the pre('save') middleware to hash the password

    const token = generateToken(user);
    res.json({ token, name: user.name, role: user.role });

  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ msg: 'Server error' });
  }
});


// ------------------ LOGIN ------------------
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ field: 'email', msg: 'Email not found' });
    }

    // ✅ Using comparePassword from the model
    const isMatch = await user.comparePassword(password);

    // Debug log (optional)
    console.log("Entered Password:", password);
    console.log("DB Stored (Hashed):", user.password);
    console.log("Match result:", isMatch);

    if (!isMatch) {
      return res.status(401).json({ field: 'password', msg: 'Incorrect password' });
    }

    const token = generateToken(user);
    res.json({ token, name: user.name, role: user.role });

  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ msg: 'Server error' });
  }
});


// ------------------ FORGOT PASSWORD ------------------
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: 'User not found' });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });

  const resetLink = `${process.env.BASE_URL}/reset-password/${token}`;
  const html = `
    <div style="font-family: 'Segoe UI', sans-serif; max-width: 600px; margin: auto; border: 1px solid #e0e0e0; padding: 20px; border-radius: 10px;">
      <h2 style="color: teal;">Employee Dashboard - Password Reset</h2>
      <p>Hi <strong>${user.name}</strong>,</p>
      <p>We received a request to reset your password. Click the button below to choose a new password:</p>
      <a href="${resetLink}" style="display: inline-block; background-color: teal; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none; font-weight: bold;">
        Reset Password
      </a>
      <p style="margin-top: 20px;">If you didn’t request this, you can safely ignore this email.</p>
      <hr />
      <p style="font-size: 12px; color: #888;">This link will expire in 15 minutes. Do not share it with anyone.</p>
      <p style="font-size: 12px; color: #888;">© ${new Date().getFullYear()} Employee Dashboard. All rights reserved.</p>
    </div>
  `;

  try {
    await sendEmail(user.email, 'Reset Your Password - Employee Dashboard', html);
    res.json({ message: 'Reset email sent. Check your inbox.' });
  } catch (err) {
    console.error('Email send error:', err);
    res.status(500).json({ message: 'Error sending email' });
  }
});

// ------------------ RESET PASSWORD ------------------
router.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ message: 'Invalid or expired token' });

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password has been reset successfully.' });
  } catch (err) {
    return res.status(400).json({ message: 'Invalid or expired token.' });
  }
});

// ------------------ GET USER PROFILE ------------------

router.get('/account-info', protect, getAccountInfo);

// Change Password Route
router.post('/change-password', protect, changePassword);

// Delete Account Route
router.delete('/delete-account', protect, deleteAccount);

module.exports = router;
