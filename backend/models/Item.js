const mongoose = require('mongoose');

// Define the schema for the Item model
const itemSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, 'Title is required'], // Ensures the field is mandatory
      trim: true, // Removes unnecessary whitespace
      maxlength: [100, 'Title cannot exceed 100 characters'], // Limits input length
    },
    description: {
      type: String,
      required: [true, 'Description is required'],
      trim: true,
      maxlength: [500, 'Description cannot exceed 500 characters'],
    },
    location: {
      type: String,
      required: [true, 'Location is required'],
      trim: true,
      maxlength: [200, 'Location cannot exceed 200 characters'],
    },
    category: {
      type: String,
      enum: {
        values: ['lost', 'found'], // Restricts input to only these two values
        message: '{VALUE} is not supported. Choose either "lost" or "found".',
      },
      required: [true, 'Category is required'],
    },
    image: {
      type: String, // URL of the uploaded image (optional)
      default: null, // Default value if no image is provided
    },
    date: {
      type: Date,
      default: Date.now, // Automatically sets the current date if not provided
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId, // Reference to the user who reported the item
      ref: 'User', // Links to the User model
      required: [true, 'User ID is required'], // Ensures the item is tied to a user
    },
  },
  {
    timestamps: true, // Adds createdAt and updatedAt fields automatically
  }
);

// Create and export the Item model
const Item = mongoose.model('Item', itemSchema);
module.exports = Item;
