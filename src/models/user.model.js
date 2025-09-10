const mongoose = require('mongoose');

const RefreshTokenSchema = new mongoose.Schema({
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

// Basic user schema. Add fields as needed (roles, permissions, metadata)
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, default: '' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' }, // added enum
  refreshTokens: [RefreshTokenSchema] // store refresh tokens (or use sessions/redis)
}, {
  timestamps: true
});

UserSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.refreshTokens;
  return obj;
};

module.exports = mongoose.model('User', UserSchema);
