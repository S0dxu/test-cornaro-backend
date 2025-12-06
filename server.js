const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;

app.use(express.json());
app.use(cors({
  origin: "*",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

mongoose.connect(process.env.MONGO_URI);

const emailCooldown = new Map();
const failedAttempts = new Map();

const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  instagram: String,
  schoolEmail: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  profileImage: String,
  isAdmin: { type: Boolean, default: false }
});
const User = mongoose.model("User", userSchema);

const codeSchema = new mongoose.Schema({
  schoolEmail: { type: String, required: true },
  code: String,
  expiresAt: Date
});
const VerificationCode = mongoose.model("VerificationCode", codeSchema);

const infoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ["info", "alert"], default: "info" },
  createdAt: { type: Date, default: Date.now },
  createdBy: String
});
const Info = mongoose.model("Info", infoSchema);

const createLimiter = (max) =>
  rateLimit({ windowMs: 60000, max, standardHeaders: true, legacyHeaders: false });

const authLimiter = createLimiter(30);

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

function verifyAdmin(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token mancante" });
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    User.findOne({ schoolEmail: payload.id }).then(user => {
      if (!user) return res.status(401).json({ message: "Utente non trovato" });
      if (!user.isAdmin) return res.status(403).json({ message: "Non sei admin" });
      req.user = user;
      next();
    });
  } catch { return res.status(401).json({ message: "Token non valido" }); }
}

function generateCode() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let c = "";
  for (let i = 0; i < 6; i++) c += chars[Math.floor(Math.random() * chars.length)];
  return c;
}

function isValidSchoolEmail(email) {
  email = email.normalize("NFKC").replace(/[^\x00-\x7F]/g, "").toLowerCase().trim();
  if (/[\r\n]/.test(email)) return false;
  return /^[^@]+@studenti\.liceocornaro\.edu\.it$/.test(email);
}

const sendMailWithTimeout = (mailOptions, timeout = 10000) => {
  return Promise.race([
    transporter.sendMail(mailOptions),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Timeout invio email")), timeout)
    )
  ]);
};

app.post("/register/request", async (req, res) => {
  const { schoolEmail } = req.body;
  if (!schoolEmail) return res.status(400).json({ message: "Email richiesta" });
  if (!isValidSchoolEmail(schoolEmail)) return res.status(400).json({ message: "Email non valida" });

  const exists = await User.findOne({ schoolEmail });
  if (exists) return res.status(400).json({ message: "Utente già registrato" });

  const now = Date.now();
  if (emailCooldown.has(schoolEmail) && now - emailCooldown.get(schoolEmail) < 60000)
    return res.status(429).json({ message: "Attendi 60 secondi" });

  const code = generateCode();
  const expiresAt = new Date(now + 10 * 60000);

  try {
    await sendMailWithTimeout({
      from: process.env.SMTP_USER,
      to: schoolEmail,
      subject: "Codice di verifica App Cornaro",
      text: `Il tuo codice: ${code}`
    }, 10000);
  } catch {
    return res.status(400).json({ message: "Email inesistente o problema nell'invio" });
  }

  await VerificationCode.findOneAndUpdate(
    { schoolEmail },
    { code, expiresAt },
    { upsert: true }
  );

  emailCooldown.set(schoolEmail, now);
  res.json({ message: "Codice inviato" });
});

app.post("/register/verify", authLimiter, async (req, res) => {
  const { firstName, lastName, instagram, schoolEmail, password, code, profileImage } = req.body;
  if (!firstName || !lastName || !schoolEmail || !password || !code) return res.status(400).json({ message: "Campi obbligatori mancanti" });
  const key = schoolEmail;
  const fail = failedAttempts.get(key) || { count: 0, lock: 0 };
  if (fail.lock > Date.now()) return res.status(429).json({ message: "Bloccato temporaneamente" });
  const record = await VerificationCode.findOne({ schoolEmail });
  if (!record || record.code !== code) {
    fail.count++;
    if (fail.count >= 5) {
      fail.lock = Date.now() + 600000;
      failedAttempts.set(key, fail);
      return res.status(429).json({ message: "Troppi tentativi, riprova tra 10 minuti" });
    }
    failedAttempts.set(key, fail);
    return res.status(400).json({ message: "Codice non valido" });
  }
  if (record.expiresAt < new Date()) return res.status(400).json({ message: "Codice scaduto" });
  const exists = await User.findOne({ schoolEmail });
  if (exists) return res.status(400).json({ message: "Utente già esistente" });
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ firstName, lastName, instagram: instagram || "", schoolEmail, password: hashed, profileImage: profileImage || "" });
  await VerificationCode.deleteOne({ schoolEmail });
  failedAttempts.delete(key);
  const token = jwt.sign({ id: schoolEmail }, SECRET_KEY);
  res.status(201).json({ message: "Registrazione completata", token });
});

app.post("/login", authLimiter, async (req, res) => {
  const { schoolEmail, password } = req.body;
  if (!schoolEmail || !password) return res.status(400).json({ message: "Campi mancanti" });
  const user = await User.findOne({ schoolEmail });
  if (!user) return res.status(400).json({ message: "Credenziali errate" });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: "Credenziali errate" });
  const token = jwt.sign({ id: schoolEmail }, SECRET_KEY);
  res.json({ message: "Login riuscito", token, firstName: user.firstName, lastName: user.lastName, instagram: user.instagram || "", schoolEmail: user.schoolEmail, profileImage: user.profileImage || "" });
});

app.post("/logout", async (req, res) => res.json({ message: "Logout effettuato" }));

app.post("/admin/clean-codes", verifyAdmin, async (req, res) => {
  const result = await VerificationCode.deleteMany({ expiresAt: { $lt: new Date() } });
  res.json({ eliminati: result.deletedCount });
});

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 2 * 1024 * 1024 } });

app.listen(PORT);
