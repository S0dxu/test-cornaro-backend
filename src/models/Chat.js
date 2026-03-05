const mongoose = require("mongoose");

const schema = new mongoose.Schema({
  seller: { type: String, required: true, index: true },
  buyer: { type: String, required: true, index: true },
  bookId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Book",
    required: true
  },
  lastMessage: {
    text: String,
    sender: String,
    createdAt: Date,
    seen: { type: Boolean, default: false } 
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
schema.index(
  { seller: 1, buyer: 1, bookId: 1 },
  { unique: true, partialFilterExpression: { bookId: { $type: "objectId" } } }
);

module.exports = mongoose.model("Chat", schema);