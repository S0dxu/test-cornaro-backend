const mongoose = require("mongoose");

const schema = new mongoose.Schema({
  title: { type: String, required: true }, 
  message: { type: String, required: true }, 
  type: { type: String, enum: ["info","alert"], default: "info" }, 
  createdAt: { type: Date, default: Date.now }, 
  createdBy: String, 
  notified: { type: Boolean, default: false }
});

module.exports = mongoose.model("Info", schema);