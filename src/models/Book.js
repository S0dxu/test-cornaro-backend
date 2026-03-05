const mongoose = require("mongoose");

const schema = new mongoose.Schema({
  title: { type: String,  required: true }, 
  condition: { type: String }, 
  price: { type: Number, required: true }, 
  subject: { type: String }, 
  grade: { type: String }, 
  images: [String], 
  likes: { type: Number, default: 0 }, 
  likedBy: { type: [String], default: [] },
  createdAt: { type: Date, default: Date.now }, 
  createdBy: String, 
  description: { type: String, maxlength: 1000 }, 
  isbn: { type: String }
});

schema.index({ title: "text", author: "text" });

module.exports = mongoose.model("Book", schema);