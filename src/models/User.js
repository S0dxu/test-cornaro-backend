const mongoose = require("mongoose");
const { encrypt } = require("../services/encryption");
const bcrypt = require("bcrypt");

const schema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  instagram: String,
  schoolEmail: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  profileImage: String,
  isAdmin: { type: Boolean, default: false },
  averageRating: { type: Number, default: 0 },
  ratingsCount: { type: Number, default: 0 },
  credits: { type: Number, default: 50, min: 0 },
  lastSeenAt: { type: Date, default: null },
  lastSeenUpdateAt: { type: Date, default: null },
  active: { type: Boolean, default: true },
  notifications: {
    push: { type: Boolean, default: true },
    email: { type: Boolean, default: true }
  },
  premiumUntil: { type: Date, default: null },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

schema.pre("save", async function () {
  if (this.isModified("firstName")) this.firstName = encrypt(this.firstName);
  if (this.isModified("lastName")) this.lastName = encrypt(this.lastName);
  if (this.isModified("password")) this.password = await bcrypt.hash(this.password, 12);
});

module.exports = mongoose.model("User", schema);