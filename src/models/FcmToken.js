const mongoose = require("mongoose");

const schema = new mongoose.Schema({
  schoolEmail: { type: String, required: true, index: true },
  token: { type: String, required: true, unique: true },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("FcmToken", schema);