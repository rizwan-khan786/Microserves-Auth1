const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');

const User = require('../models/user.model');
const { signAccess, signRefresh, verifyRefresh } = require('../utils/jwt');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Register
 * POST /api/v1/auth/register
 * body: { email, password, name, role }
 */
router.post('/register', [
  body('email').isEmail().withMessage('Provide a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('name').optional().isString(),
  body('role').optional().isIn(['user', 'admin']).withMessage('Role must be either "user" or "admin"')
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { email, password, name, role } = req.body;

    // Check if user already exists
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ success: false, message: 'Email already registered' });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user with role (default to 'user' if not provided)
    const user = new User({
      email,
      password: hashedPassword,
      name: name || '',
      role: role || 'user'
    });

    await user.save();

    // Generate tokens
    const accessToken = signAccess({ id: user._id, email: user.email, role: user.role });
    const refreshToken = signRefresh({ id: user._id });

    // Store refresh token
    user.refreshTokens.push({ token: refreshToken });
    await user.save();

    res.status(201).json({
      success: true,
      data: { user: user.toJSON(), accessToken, refreshToken }
    });
  } catch (err) {
    next(err);
  }
});


/**
 * Login
 * POST /api/v1/auth/login
 * body: { email, password }
 */
router.post('/login', [
  body('email').isEmail(),
  body('password').exists()
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const accessToken = signAccess({ id: user._id, email: user.email, role: user.role });
    const refreshToken = signRefresh({ id: user._id });

    user.refreshTokens.push({ token: refreshToken });
    await user.save();

    res.json({ success: true, data: {user: user.toJSON(), accessToken, refreshToken } });
  } catch (err) {
    next(err);
  }
});

// /**
//  * Refresh
//  * POST /api/v1/auth/refresh
//  * body: { refreshToken }
//  */
// router.post('/refresh', [
//   body('refreshToken').exists()
// ], async (req, res, next) => {
//   try {
//     const { refreshToken } = req.body;
//     if (!refreshToken) return res.status(400).json({ success: false, message: 'refreshToken required' });

//     // verify token
//     let payload;
//     try {
//       payload = verifyRefresh(refreshToken);
//     } catch (err) {
//       return res.status(401).json({ success: false, message: 'Invalid refresh token' });
//     }

//     const user = await User.findById(payload.id);
//     if (!user) return res.status(401).json({ success: false, message: 'User not found' });

//     const found = user.refreshTokens.find(rt => rt.token === refreshToken);
//     if (!found) {
//       // token reuse/attack - clear all user's refresh tokens as precaution
//       user.refreshTokens = [];
//       await user.save();
//       logger.warn('Refresh token reuse detected for user', user._id);
//       return res.status(401).json({ success: false, message: 'Refresh token not recognized' });
//     }

//     // Optionally: rotate tokens (issue new refresh token and remove the old one)
//     // For simplicity, remove old and add new
//     user.refreshTokens = user.refreshTokens.filter(rt => rt.token !== refreshToken);
//     const newRefresh = signRefresh({ id: user._id });
//     user.refreshTokens.push({ token: newRefresh });
//     await user.save();

//     const accessToken = signAccess({ id: user._id, email: user.email, role: user.role });

//     res.json({ success: true, data: { accessToken, refreshToken: newRefresh } });
//   } catch (err) {
//     next(err);
//   }
// });


/**
 * Login
 * POST /api/v1/auth/login
 * body: { email, password }
 */
router.post('/login', [
  body('email').isEmail(),
  body('password').exists()
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) 
      return res.status(400).json({ success: false, errors: errors.array() });

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) 
      return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) 
      return res.status(401).json({ success: false, message: 'Invalid credentials' });

    // Always issue fresh tokens on login
    const accessToken = signAccess({ id: user._id, email: user.email, role: user.role });
    const refreshToken = signRefresh({ id: user._id });

    // Replace refresh tokens with new one (avoid duplicates)
    user.refreshTokens = [{ token: refreshToken }];
    await user.save();

    res.json({ success: true, data: { user: user.toJSON(), accessToken, refreshToken } });
  } catch (err) {
    next(err);
  }
});

/**
 * Refresh
 * POST /api/v1/auth/refresh
 * body: { refreshToken }
 */
router.post('/refresh', [
  body('refreshToken').exists()
], async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) 
      return res.status(400).json({ success: false, message: 'refreshToken required' });

    let payload;
    try {
      payload = verifyRefresh(refreshToken);
    } catch (err) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }

    const user = await User.findById(payload.id);
    if (!user) 
      return res.status(401).json({ success: false, message: 'User not found' });

    const found = user.refreshTokens.find(rt => rt.token === refreshToken);
    if (!found) {
      return res.status(401).json({ success: false, message: 'Refresh token not recognized' });
    }

    // Do NOT remove/rotate token — just issue new access token
    const accessToken = signAccess({ id: user._id, email: user.email, role: user.role });

    res.json({ success: true, data: { accessToken, refreshToken } });
  } catch (err) {
    next(err);
  }
});

/**
 * Logout
 * POST /api/v1/auth/logout
 * body: { refreshToken }
 */
router.post('/logout', [
  body('refreshToken').exists()
], async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ success: false, message: 'refreshToken required' });

    // Remove refresh token from user's list
    try {
      const payload = verifyRefresh(refreshToken);
      const user = await User.findById(payload.id);
      if (user) {
        user.refreshTokens = user.refreshTokens.filter(rt => rt.token !== refreshToken);
        await user.save();
      }
    } catch (err) {
      // ignore invalid token - consider it logged out
    }

    res.json({ success: true, message: 'Logged out' });
  } catch (err) {
    next(err);
  }
});

/**
 * Protected demo route
 * GET /api/v1/auth/me
 */
const authMiddleware = require('../middleware/auth.middleware');

router.get('/me', authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, data: user.toJSON() });
  } catch (err) {
    next(err);
  }
});



module.exports = router;
