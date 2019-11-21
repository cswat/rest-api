// Require bcrypt.js - Hashing User Passwords
const bcryptjs = require('bcryptjs');
const auth = require('basic-auth');

// Database
const db = require('../db');
const { User } = db.models;

// Middleware - Authenticate User
const authenticateUser = async (req, res, next) => {

  let message = null;

  // Parse user's credentials from Authorization header.
  const credentials = auth(req);

  // If user's credentials are available...
  if (credentials) {

    /* Attempt to retrieve user from data store by their username (i.e. user's "key" from Authorization header).
    const user = await User.find(u => u.username === credentials.emailAddress); */

    const user = await User.findOne({
        where: { emailAddress: credentials.name }
    });

    // If a user was successfully retrieved from data store...
    if (user) {

      // Use bcryptjs npm package to compare user's password (from Authorization header) to user's password that was retrieved from data store.
      const authenticated = bcryptjs.compareSync(credentials.pass, user.password);

      // If passwords match...
      if (authenticated) {
        req.currentUser = user;
      } else {
        message = `Authentication failure for username: ${user.emailAddress}`;
      }
    } else {
      message = `User not found for username: ${credentials.name}`;
    }
  } else {
    message = 'Oops, no authorization header was found';
  }

  // If user authentication failed...
  if (message) {
    console.warn(message);
    // Return a response with a 401 Unauthorized HTTP status code.
    res.status(401).json({ message: 'Access Denied' });
  } else {
    next();
  }

};

module.exports = authenticateUser;
