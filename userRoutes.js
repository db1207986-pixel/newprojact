const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

// 1. Register User
router.post('/register', async (req, res) => {
  try {
    const { number, password, balance } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ number });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      number,
      password: hashedPassword,
      balance: balance || 0
    });

    await newUser.save();
    res.status(201).json({ message: 'User created successfully' });

  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// 2. Login User
router.post('/login', async (req, res) => {
  try {
    const { number, password } = req.body;

    // Find user
    const user = await User.findOne({ number });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '24h' });

    res.json({ token, message: 'Logged in successfully', balance: user.balance });

  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// 3. Get User Balance (Protected Route)
router.get('/balance', async (req, res) => {
  try {
    // Get token from headers
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access Denied' });

    // Verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    
    // Find user
    const user = await User.findById(verified.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({ number: user.number, balance: user.balance });

  } catch (error) {
    res.status(400).json({ message: 'Invalid Token' });
  }
});

// 4. Update Balance (Protected Route)
router.put('/update-balance', async (req, res) => {
  try {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access Denied' });

    const verified = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    const { amount } = req.body; // Add or subtract amount

    const user = await User.findById(verified.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.balance += amount;
    await user.save();

    res.json({ message: 'Balance updated successfully', newBalance: user.balance });

  } catch (error) {
    res.status(400).json({ message: 'Invalid Token or Server Error' });
  }
});

module.exports = router;
