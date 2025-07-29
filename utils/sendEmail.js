// utils/sendEmail.js
const nodemailer = require("nodemailer");

const sendEmail = async (to, subject, html) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,   // your Gmail address
      pass: process.env.EMAIL_PASS    // Gmail App Password
    }
  });

  await transporter.sendMail({
    from: `"Employee Dashboard" <${process.env.EMAIL_USER}>`,
    to,
    subject,
    html,
  });
};

module.exports = sendEmail;
