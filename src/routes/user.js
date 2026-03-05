const express = require("express");
const { verifyUser, postLimiterIP } = require("../middlewares/auth");
const User = require("../models/User");
const PasswordReset = require("../models/PasswordReset");
const router = express.Router();
const { encrypt, decrypt } = require("../services/encryption");
const bcrypt = require("bcrypt");
const { sendEmailViaBridge } = require("../services/email");
const crypto = require("crypto");

function generateCode() {
  return crypto.randomBytes(3).toString("hex").toUpperCase();
}

router.post("/notifications", verifyUser, async (req, res) => {
  const { push, email } = req.body;
  if (push === undefined && email === undefined)
    return res.status(400).json({ message: "Nessun dato inviato" });
  const update = {};
  if (push !== undefined) update["notifications.push"] = push;
  if (email !== undefined) update["notifications.email"] = email;
  await User.updateOne({ _id: req.user._id }, update);
  res.json({ message: "Preferenze aggiornate", updated: update });
});

router.get("/profile/:email", verifyUser, async (req, res) => {
  const email = req.params.email;
  const user = await User.findOne(
    { schoolEmail: email, active: true },
    { firstName: 1, lastName: 1, profileImage: 1, instagram: 1, isReliable: 1, averageRating: 1, ratingsCount: 1, lastSeenAt: 1 }
  ).lean();
  if (!user) return res.status(404).json({ message: "Utente non trovato" });
  const ONLINE_THRESHOLD = 5 * 60 * 1000;
  const isOnline = user.lastSeenAt && Date.now() - new Date(user.lastSeenAt).getTime() < ONLINE_THRESHOLD;
  res.status(200).json({
    ...user,
    firstName: decrypt(user.firstName),
    lastName: decrypt(user.lastName),
    instagram: user.instagram ? decrypt(user.instagram) : ""
  });
});

router.get("/is-admin", verifyUser, async (req,res)=> res.json({ 
    isAdmin:req.user.isAdmin
}));

router.post("/user/deactivate", verifyUser, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ message: "Password richiesta" });

  const user = await User.findById(req.user._id);
  if (!user || !user.active) return res.status(400).json({ message: "Utente non trovato o già disattivato" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: "Password errata" });

  await User.updateOne({ _id: user._id }, { active: false });
  res.json({ message: "Account disattivato correttamente" });
});

router.post("/password-reset/request", postLimiterIP, async (req, res) => {

  const { schoolEmail } = req.body;

  const user = await User.findOne({
    schoolEmail,
    active: true
  });

  if (!user) {
    return res.status(200).json({
      message: "Se l'email esiste riceverai un codice"
    });
  }

  const code = generateCode();
  const expiresAt = new Date(Date.now() + 10 * 60000);

  await PasswordReset.findOneAndUpdate(
    { schoolEmail },
    { code, expiresAt },
    { upsert: true }
  );

  await sendEmailViaBridge({
    to: schoolEmail,
    subject: "Reset password Cornaro",
    html: `<h2>${code}</h2>`
  });

  res.json({
    message: "Codice inviato"
  });

});

router.post("/password-reset/confirm", postLimiterIP, async (req, res) => {

  const { schoolEmail, code, newPassword } = req.body;

  const record = await PasswordReset.findOne({ schoolEmail });

  if (!record || record.code !== code) {
    return res.status(400).json({
      message: "Codice non valido"
    });
  }

  if (record.expiresAt < new Date()) {
    return res.status(400).json({
      message: "Codice scaduto"
    });
  }

  const user = await User.findOne({
    schoolEmail,
    active: true
  });

  if (!user) {
    return res.status(400).json({
      message: "Utente non trovato"
    });
  }

  user.password = newPassword;

  await user.save();

  await PasswordReset.deleteOne({ schoolEmail });

  res.json({
    message: "Password aggiornata"
  });

});

module.exports = router;