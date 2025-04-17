
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { body, validationResult } = require('express-validator'); // For input validation
const rateLimit = require('express-rate-limit'); // For rate-limiting
const helmet = require('helmet'); // For security headers
const winston = require('winston'); // For logging

const router = express.Router();

// Logger setup for security events
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.File({ filename: 'security.log' })],
});

// Rate limiter for login attempts (5 attempts per hour)
const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit each IP to 5 requests per hour
  message: 'Too many login attempts. Please try again later.',
});

// Middleware to enforce HTTPS in production
if (process.env.NODE_ENV === 'production') {
  const enforce = require('express-sslify');
  router.use(enforce.HTTPS({ trustProtoHeader: true }));
}

// Use Helmet to set security headers
router.use(helmet());

// Register a new user with input validation
router.post(
  '/register',
  [
    body('name')
      .trim()
      .isLength({ min: 3 })
      .withMessage('Name must be at least 3 characters'),
    body('email').isEmail().withMessage('Invalid email address'),
    body('password')
      .isStrongPassword({
        minLength: 10,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
      })
      .withMessage('Password must be strong'),
  ],
  async (req, res) => {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { name, email, password } = req.body;

      // Check if the user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'User with this email already exists' });
      }

      // Create a new user
      const newUser = new User({ name, email, password });

      // Save the user to the database
      await newUser.save();

      // Respond with success message
      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }
);

// Login an existing user with rate-limiting
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email }).select('+password'); // Include password field
    if (!user || !(await bcrypt.compare(password, user.password))) {
      // Log failed login attempt
      logger.warn(`Failed login attempt for email: ${email}`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate a JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Respond with the token
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
