const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // For password hashing

// Define the schema for the User model
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      maxlength: [50, 'Name cannot exceed 50 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true, // Ensures no two users can have the same email
      lowercase: true, // Converts email to lowercase for consistency
      trim: true, // Removes leading and trailing whitespace
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        'Please provide a valid email address',
      ], // Validates email format
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [10, 'Password must be at least 10 characters'], // Increased minimum length
      validate: {
        validator: function (value) {
          // Regex to enforce password complexity
          const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/;
          return passwordRegex.test(value);
        },
        message:
          'Password must be at least 10 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.',
      },
      select: false, // Prevents password from being returned in queries by default
    },
    role: {
      type: String,
      enum: ['user', 'admin'], // Restricts roles to 'user' or 'admin'
      default: 'user', // Default role is 'user'
    },
  },
  {
    timestamps: true, // Adds createdAt and updatedAt fields automatically
  }
);

// Middleware to hash the password before saving
userSchema.pre('save', async function (next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(10); // Generate a salt for hashing
    this.password = await bcrypt.hash(this.password, salt); // Hash the password
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare passwords during login
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password); // Returns true if passwords match
};

// Create and export the User model
const User = mongoose.model('User', userSchema);
module.exports = User;
