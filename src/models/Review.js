const mongoose = require("mongoose");

const schema = new mongoose.Schema({
  reviewer: { type: String, required: true },
  seller: { type: String, required: true },
  rating: { type: Number, min: 1, max: 5, required: true },
  comment: { type: String, maxlength: 500 },
  createdAt: { type: Date, default: Date.now },
  isAutomatic: { type: Boolean, default: false }
});

schema.index({ reviewer: 1, reviewed: 1 }, { unique: true });

module.exports = mongoose.model("Review", schema);