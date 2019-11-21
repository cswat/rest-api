// Require Express
const express = require('express');
// Require Express Router
const router = express.Router();

const bcrypt = require('bcryptjs');

// Require a Validation Library
const { validationResult } = require('express-validator');

// Database
const db = require('../models');
const { User } = db;

// Authentication Middleware 
const authenticateUser = require('../middleware/authenticateUser');

// Validation Middleware 
const checkUser = require('../middleware/checkUser');

// Return currently authenticated user
router.get('/users', authenticateUser, async (req, res, next) => {
  try {
    const user = await req.currentUser;
    res.status(200).json({
      firstName: user.firstName,
      lastName: user.lastName,
      emailAddress: user.emailAddress
    });
  } catch (err) {
    console.error("There's been an error: ", err);
  }
});

// Create user
router.post('/users', checkUser, (req, res) => {

  // Attempt to get  validation result from Request object.
  const errors = validationResult(req);

  // For validation errors
  if (!errors.isEmpty()) {
    // Use the Array `map()` method to get a list of error messages.
    const errorMessages = errors.array().map(error => error.msg);

    // Return validation errors to client
    return res.status(400).json({ errors: errorMessages });
  }

  const user = req.body;
  user.password = bcrypt.hashSync(user.password);

  User.create(user);
  res.location(`/`).status(201).end();

});

// Export
module.exports = router;
