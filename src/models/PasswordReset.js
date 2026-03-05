const mongoose = require("mongoose");

const passwordResetSchema = new mongoose.Schema({
  schoolEmail: { 
    type: String, 
    required: true 
  }, 
  code: String, 
  expiresAt: Date
});

module.exports = mongoose.model("PasswordReset", passwordResetSchema);