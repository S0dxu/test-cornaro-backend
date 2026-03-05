const express = require("express");
const { verifyAdmin } = require("../middleware/auth");
const VerificationCode = require("../models/VerificationCode");
const Message = require("../models/Message");
const router = express.Router();

router.post("/clean-codes", verifyAdmin, async (req, res) => {
  const result = await VerificationCode.deleteMany({ expiresAt: { $lt: new Date() } });
  res.json({ eliminati: result.deletedCount });
});

router.post("/check-new-messages", verifyAdmin, async (req, res) => {
  const newMessages = await Message.find({ read: false });
  res.json({ newMessages: newMessages.length });
});

module.exports = router;