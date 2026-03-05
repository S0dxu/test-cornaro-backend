const express = require("express");
const { postLimiterUser, verifyUser, verifyAdmin } = require("../middlewares/auth");
const FcmToken = require("../models/FcmToken");
const router = express.Router();
const Message = require("../models/Message");
const User = require("../models/User");
const Info = require("../models/Info");
const admin = require("firebase-admin");

router.post("/fcm/register", verifyUser, async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: "Token FCM mancante" });
  await FcmToken.findOneAndUpdate({ token }, { schoolEmail: req.user.schoolEmail, updatedAt: new Date() }, { upsert: true });
  res.json({ message: "Token FCM salvato" });
});

router.post("/fcm/check-new-messages", verifyAdmin, postLimiterUser, async (req, res) => {
  let sent = 0;
  const messages = await Message.find({ notified: false }).populate("chatId").limit(50);
  const imgurRegex = /https:\/\/i\.imgur\.com\/\S+\.(?:png|jpg|jpeg|gif)/i;
  await Promise.all(messages.map(async (msg) => {
    if (!msg.chatId) return;
    const chat = msg.chatId;
    const receiverEmail = chat.seller === msg.sender ? chat.buyer : chat.seller;
    const receiverUser = await User.findOne({ schoolEmail: receiverEmail });
    if (!receiverUser || !receiverUser.notifications.push) { msg.notified = true; return msg.save(); }
    const tokens = await FcmToken.find({ schoolEmail: receiverEmail });
    const senderUser = await User.findOne({ schoolEmail: msg.sender });
    const match = msg.text.match(imgurRegex);
    const imageUrl = match ? match[0] : null;
    await Promise.all(tokens.map(async (t) => {
      try {
        const payload = { token: t.token, notification: { title: `${senderUser.firstName} ${senderUser.lastName}`, body: msg.text.length > 80 ? msg.text.slice(0, 80) + "…" : msg.text, ...(imageUrl ? { image: imageUrl } : {}) }, data: { chatId: msg.chatId._id.toString(), username: `${senderUser.firstName} ${senderUser.lastName}`, avatar: senderUser.profileImage } };
        await admin.messaging().send(payload);
        sent++;
      } catch (e) {
        if (e.code === "messaging/registration-token-not-registered") await FcmToken.deleteOne({ token: t.token });
      }
    }));
    msg.notified = true;
    await msg.save();
  }));
  const infos = await Info.find({ notified: { $ne: true } }).sort({ createdAt: -1 }).limit(50);
  await Promise.all(infos.map(async (info) => {
    const tokens = await FcmToken.find();
    await Promise.all(tokens.map(async (t) => {
      const user = await User.findOne({ schoolEmail: t.schoolEmail });
      if (!user || !user.notifications.push) return;
      try {
        const payload = { token: t.token, notification: { title: info.title, body: info.message.length > 80 ? info.message.slice(0, 80) + "…" : info.message }, data: { infoId: info._id.toString(), type: info.type || "info" } };
        await admin.messaging().send(payload);
        sent++;
      } catch (e) {
        if (e.code === "messaging/registration-token-not-registered") await FcmToken.deleteOne({ token: t.token });
      }
    }));
    info.notified = true;
    await info.save();
  }));
  res.json({ checkedMessages: messages.length, checkedInfos: infos.length, notificationsSent: sent });
});

router.post("/user/notifications", verifyUser, async (req, res) => {
  const { push, email } = req.body;
  if (push === undefined && email === undefined) return res.status(400).json({ message: "Nessun dato inviato" });
  const update = {};
  if (push !== undefined) update["notifications.push"] = !!push;
  if (email !== undefined) update["notifications.email"] = !!email;
  await User.updateOne({ schoolEmail: req.user.schoolEmail }, update);
  res.json({ message: "Preferenze aggiornate", notifications: update });
});

router.get("/user/notifications", verifyUser, async (req,res) => {
  res.json(req.user.notifications);
});

module.exports = router;