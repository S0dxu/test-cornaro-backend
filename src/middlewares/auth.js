const jwt = require("jsonwebtoken");
const User = require("../models/User");
const Chat = require("../models/Chat");
const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");
const { SECRET_KEY } = require("../config/env");

async function verifyUser(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token mancante" });

  try {
    const payload = jwt.verify(token, SECRET_KEY);
    const user = await User.findOne({ schoolEmail: payload.id });
    
    if (!user) return res.status(401).json({ message: "Utente non trovato" });
    
    if (!user.active) return res.status(403).json({ message: "Account disattivato" });

    const now = Date.now();
    const UPDATE_INTERVAL = 5 * 60 * 1000;

    if (!user.lastSeenUpdateAt || now - user.lastSeenUpdateAt.getTime() > UPDATE_INTERVAL) {
      User.updateOne(
        { _id: user._id },
        { lastSeenAt: new Date(now), lastSeenUpdateAt: new Date(now) }
      ).catch(() => {});
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({ message: "Token non valido" });
  }
}

async function verifyChatAccess(req, res, next) {
  try {
    const chat = await Chat.findById(req.params.chatId);
    if (!chat) return res.status(404).json({ message: "Chat non trovata" });
    const email = req.user.schoolEmail;
    if (req.user.isAdmin || chat.seller === email || chat.buyer === email) {
      req.chat = chat;
      return next();
    }
    return res.status(403).json({ message: "Accesso non consentito" });
  } catch {
    return res.status(400).json({ message: "Chat ID non valido" });
  }
}

function verifyAdmin(req, res, next) {
  verifyUser(req, res, () => {
    if (!req.user.isAdmin)
      return res.status(403).json({ message: "Non sei admin" });
    next();
  });
}

const postLimiterIP = rateLimit({
  windowMs: 1000,
  max: 2,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  handler: (req, res) => {
    res.status(429).json({ message: "Limite richieste superato, riprova tra 1 secondo" });
  }
});

const postLimiterUser = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  keyGenerator: ipKeyGenerator,
  message: { message: "Troppi richieste, riprova più tardi" },
});

module.exports = { verifyUser, verifyAdmin, postLimiterUser, verifyChatAccess, postLimiterIP };