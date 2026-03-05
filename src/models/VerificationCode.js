const mongoose = require("mongoose");

const schema = new mongoose.Schema({
  schoolEmail: { 
    type: String, 
    required: true 
  }, 
  code: String, 
  expiresAt: Date
});

schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("VerificationCode", schema);