const mongoose = require('mongoose');
const logger = require('../utils/logger');

const mongoUri = process.env.MONGO_URI || 'mongodb+srv://rizwanikhan63:root@cluster0.n0mstat.mongodb.net/authdb?retryWrites=true&w=majority&appName=Cluster0';

const connectDB = async () => {
  try {
    await mongoose.connect(mongoUri, {
    //   useNewUrlParser: true,
    //   useUnifiedTopology: true
    });
    logger.info('Connected to MongoDB');
  } catch (err) {
    logger.error('MongoDB connection error', err);
    process.exit(1);
  }
};

module.exports = connectDB;
