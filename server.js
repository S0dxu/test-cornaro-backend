const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
require("dotenv").config();

//TODO email spoofing possibile, regex email troppo permissiva, 
//TODO nessuna protezione da enumeration di email, cooldown basato 
//TODO su Map volatile e non persistente, brute‑force del codice OTP 
//TODO gestito in memoria e resettabile con restart, OTP non firmato e
//TODO non legato a device/IP, password policy assente, JWT senza 
//TODO scadenza, JWT con payload debole (solo id=email), assenza di 
//TODO refresh token, mancata validazione input su tutti i campi, rischio NoSQL 
//TODO injection (findOne({ schoolEmail }) senza sanitizzazione), mancanza 
//TODO di helmet e protezioni HTTP, rate‑limit globale troppo alto e poco
//TODO  mirato, nessun controllo anti‑spam su nodemailer, nessuna protezione 
//TODO CSRF, nessuna protezione contro replay dell’OTP, caricamento file senza 
//TODO controllo MIME affidabile, nessun limite di estensione o tipo file, 
//TODO nessun antivirus o sandbox per upload, possibile bypass NSFW API, 
//TODO nessuna verifica dimensioni immagine reale, uso di base64 non sicuro 
//TODO per upload, nessun controllo autenticazione su upload-imgur, nessun 
//TODO controllo sul numero di upload, nessun logging di sicurezza, nessuna 
//TODO rotazione JWT secret, gestione errori troppo generica, possibili memory 
//TODO leak da Map, dati sensibili in plain-text nei log, nessuna verifica di 
//TODO uguaglianza costante (timing attack) nei confronti dell’OTP.

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;

app.use(express.json());
app.use(cors({ methods: ["GET", "POST"], allowedHeaders: ["Content-Type"] }));

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
  createdBy: { type: String },
});
const Info = mongoose.model("Info", infoSchema);

const limiter = rateLimit({ windowMs: 60000, max: 20 });
app.use(limiter);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
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
  } catch (err) {
    return res.status(401).json({ message: "Token non valido" });
  }
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

app.post("/register/request", async (req, res) => {
  const { schoolEmail } = req.body;
  if (!schoolEmail) return res.status(400).json({ message: "Email richiesta" });
  if (!isValidSchoolEmail(schoolEmail)) {
    return res.status(400).json({ message: "Email non valida" });
  }

  const exists = await User.findOne({ schoolEmail });
  if (exists) return res.status(400).json({ message: "Utente già registrato" });

  const now = Date.now();
  if (emailCooldown.has(schoolEmail)) {
    const diff = now - emailCooldown.get(schoolEmail);
    if (diff < 60000) return res.status(429).json({ message: "Attendi 60 secondi" });
  }

  const code = generateCode();
  const expiresAt = new Date(now + 10 * 60000);

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: schoolEmail,
      subject: "Codice di verifica App Cornaro",
      text: `Il tuo codice: ${code}`
    });
  } catch (err) {
    return res.status(400).json({ message: "Email inesistente" });
  }

  await VerificationCode.findOneAndUpdate(
    { schoolEmail },
    { code, expiresAt },
    { upsert: true }
  );

  emailCooldown.set(schoolEmail, now);
  res.json({ message: "Codice inviato" });
});

app.post("/register/verify", async (req, res) => {
  const { firstName, lastName, instagram, schoolEmail, password, code, profileImage } = req.body;

  if (!firstName || !lastName || !schoolEmail || !password || !code)
    return res.status(400).json({ message: "Tutti i campi obbligatori sono richiesti" });

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
  await new User({
    firstName,
    lastName,
    instagram: instagram || "",
    schoolEmail,
    password: hashed,
    profileImage: profileImage || ""
  }).save();

  await VerificationCode.deleteOne({ schoolEmail });
  failedAttempts.delete(key);

  const token = jwt.sign({ id: schoolEmail }, SECRET_KEY);
  res.status(201).json({ message: "Registrazione completata", token });
});

app.post("/login", async (req, res) => {
  const { schoolEmail, password } = req.body;
  if (!schoolEmail || !password) return res.status(400).json({ message: "Campi mancanti" });

  const user = await User.findOne({ schoolEmail });
  if (!user) return res.status(400).json({ message: "Credenziali errate" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: "Credenziali errate" });

  const token = jwt.sign({ id: schoolEmail }, SECRET_KEY);
  res.json({
    message: "Login riuscito",
    token,
    firstName: user.firstName,
    lastName: user.lastName,
    instagram: user.instagram || "",
    schoolEmail: user.schoolEmail,
    profileImage: user.profileImage || ""
  });
});

app.post("/logout", async (req, res) => {
  res.json({ message: "Logout effettuato" });
});

app.post("/admin/clean-codes", async (req, res) => {
  const now = new Date();
  const result = await VerificationCode.deleteMany({ expiresAt: { $lt: now } });
  res.json({ eliminati: result.deletedCount });
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

app.post("/upload-imgur", upload.single("image"), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: "File mancante" });

  try {
    const fetch = (await import("node-fetch")).default;

    const boundary = "----WebKitFormBoundaryCheckNSFW";
    const body = Buffer.concat([
      Buffer.from(`--${boundary}\r\n`),
      Buffer.from(`Content-Disposition: form-data; name="nudepic"; filename="${req.file.originalname}"\r\n`),
      Buffer.from(`Content-Type: ${req.file.mimetype}\r\n\r\n`),
      req.file.buffer,
      Buffer.from(`\r\n--${boundary}--\r\n`)
    ]);

    const nsfwResponse = await fetch("https://letspurify.askjitendra.com/send/data", {
      method: "POST",
      headers: {
        "accept": "*/*",
        "content-type": `multipart/form-data; boundary=${boundary}`,
      },
      body: body,
    });

    const nsfwData = await nsfwResponse.json();

    if (nsfwData.status) {
      return res.status(400).json({ message: "L'immagine non è consentita" });
    }

    const base64Image = req.file.buffer.toString("base64");

    const imgurResponse = await fetch("https://api.imgur.com/3/upload", {
      method: "POST",
      headers: { Authorization: `Client-ID ${process.env.IMGUR_CLIENT_ID}` },
      body: new URLSearchParams({ image: base64Image }),
    });

    const imgurData = await imgurResponse.json();
    if (imgurData.success) {
      res.json({ link: imgurData.data.link });
    } else {
      res.status(500).json({ message: "Errore caricamento Imgur" });
    }

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/add-info", verifyAdmin, async (req, res) => {
  const { title, message, type } = req.body;
  if (!title || !message) return res.status(400).json({ message: "Campi mancanti" });

  try {
    const info = new Info({
      title,
      message,
      type: type || "info",
      createdBy: req.user.schoolEmail
    });
    await info.save();
    res.status(201).json({ message: "Avviso aggiunto", info });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/get-info", async (req, res) => {
  try {
    const infos = await Info.find({}, { createdBy: 0 }) // 0 = false ovvero escludi
      .sort({ createdAt: -1 })
      .limit(15);
    res.json({ infos });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/is-admin", async (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token mancante" });

  try {
    const payload = jwt.verify(token, SECRET_KEY);
    const user = await User.findOne({ schoolEmail: payload.id });
    if (!user) return res.status(404).json({ message: "Utente non trovato" });

    res.json({ isAdmin: user.isAdmin });
  } catch (err) {
    res.status(401).json({ message: "Token non valido" });
  }
});

app.listen(PORT);
