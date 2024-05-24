// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Initialize Express app
const app = express();
app.use(bodyParser.json());
app.set('view engine', 'ejs');

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/auth-demo', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Define User schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  roles: [String],
  otp: String,
  otpExpires: Date,
});

const User = mongoose.model('User', userSchema);

// Set up nodemailer transporter with app-specific password
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'aamrakorbojoy92@gmail.com',
    pass: '**********',
  },
});

// Verify transporter configuration
transporter.verify(function(error, success) {
  if (error) {
    console.log('Error with transporter configuration:', error);
  } else {
    console.log('Server is ready to take our messages');
  }
});

// Generate OTP
function generateOTP() {
  return crypto.randomBytes(3).toString('hex');
}

// Send OTP Email
async function sendOTPEmail(email, otp) {
  const mailOptions = {
    from: 'aamrakorbojoy92@gmail.com',
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP email sent to ${email}`);
  } catch (error) {
    console.error('Error sending OTP email:', error);
  }
}

// OTP Verification Route
app.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Find user by email and check OTP
    const user = await User.findOne({ email });
    if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).send('Invalid or expired OTP');
    }

    // OTP is valid, clear OTP fields
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.send('OTP verified successfully');
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// Login with OTP Route
app.post('/login/otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Validate OTP
    const user = await User.findOne({ email });
    if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).send('Invalid or expired OTP');
    }

    // Generate JWT token
    const token = jwt.sign({ email: user.email, roles: user.roles }, 'your-secret-key');

    res.json({ token });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// Register Route
app.post('/register', async (req, res) => {
  try {
    const { email, username, password, confirmPassword, roles } = req.body;

    // Validate input fields
    if (!email || !username || !password || !confirmPassword || !roles) {
      return res.status(400).send('All fields are required');
    }

    if (password !== confirmPassword) {
      return res.status(400).send('Passwords do not match');
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send('Email already registered');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate OTP and set expiration time
    const otp = generateOTP();
    const otpExpires = Date.now() + 10 * 60 * 1000;

    // Create user object
    const user = new User({
      email,
      username,
      password: hashedPassword,
      roles,
      otp,
      otpExpires,
    });

    // Save user to database
    await user.save();

    // Send OTP email
    await sendOTPEmail(email, otp);

    res.status(201).send('User registered successfully. Check your email for the OTP.');
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// Start server
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
