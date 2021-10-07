const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const auth = require('../middleware/auth');

const { body, validationResult } = require('express-validator');

// User Model
const User = require('../models/User');
const Attendant = require('../models/Attendant');

// @route   POST    api/auth
// @desc    Auth user & get token
// @access  Public
router.post(
  '/',
  [
    body('email', 'Please enter a valid email').isEmail(),
    body('password', 'Password is required').exists(),
  ],
  async (req, res) => {
    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      let user = await User.findOne({ email });

      if (!user) {
        return res.status(400).json({ msg: 'Invalid Credentials' });
      }

      // Verify password match
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ msg: 'Invalid Credentials' });
      }

      const payload = {
        user: {
          id: user.id,
          email: user.email,
        },
      };

      // Json web token generate
      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 36000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (error) {
      console.error(error.message);
      res.status(500).send('Server Error');
    }
  }
);

// @route   GET    api/auth
// @desc    Get logged in user
// @access  Private
router.get('/', auth, async (req, res) => {
  try {
    if (req.user.name) {
      const attendant = await Attendant.findOne({
        user: req.user.id,
        email: req.user.emailAttendant,
      }).select('-password');
      res.json(attendant);
    } else {
      const user = await User.findById(req.user.id).select('-password');
      res.json(user);
    }
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server Error');
  }
});

module.exports = router;