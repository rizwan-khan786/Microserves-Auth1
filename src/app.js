

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const connectDB = require('./config/db');
const authRoutes = require('./controllers/auth.controller');
const logger = require('./utils/logger');

const app = express();

connectDB();

// Middlewares
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

const limiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Routes

app.use('/api/v1/auth', authRoutes);
app.get('/health', (req, res) => res.json({ status: 'ok', service: 'auth-service' }));

app.use((err, req, res, next) => {
  logger.error(err);
  res.status(err.status || 500).json({ success: false, message: err.message || 'Internal server error' });
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => logger.info(`Auth service running on port ${PORT}`));
}

module.exports = app;
