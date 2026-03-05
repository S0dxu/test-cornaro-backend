const mongoose = require("mongoose");

const schema = new mongoose.Schema({
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: "Chat", required: true, index: true },
  sender: { type: String, required: true },
  notified: { type: Boolean, default: false },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Message", schema);