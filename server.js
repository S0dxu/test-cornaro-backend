const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
require("dotenv").config();
const admin = require("firebase-admin");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const NodeCache = require("node-cache");
const crypto = require("crypto");
const { createClient } = require("redis");
const helmet = require("helmet");
const hpp = require("hpp");
const cluster = require("cluster");
const os = require("os");
const RedisStore = require("rate-limit-redis").default;

if (cluster.isPrimary) {
  const numCPUs = os.cpus().length;
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
  cluster.on("exit", () => cluster.fork());
} else {
  const redisClient = createClient({
    url: process.env.REDIS_URL
  });

  redisClient.on("error", (err) => {
    console.error("Redis error:", err.message);
  });

  (async () => {
    try {
      await redisClient.connect();
    } catch (err) {
      console.error("Redis connection failed:", err);
    }
  })();

  const fetch = (...args) =>
    import("node-fetch").then(({ default: fetch }) => fetch(...args));

  const ENC_KEY = Buffer.from(process.env.DATA_ENCRYPTION_KEY, "hex");
  if (ENC_KEY.length !== 32) {
    throw new Error("INVALID ENCRYPTION_KEY");
  }

  const ALGO = "aes-256-gcm";
  const CREDITS_ENABLED = false;

  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });

  const IMGUR_REGEX = /https:\/\/i\.imgur\.com\/\S+\.(?:png|jpg|jpeg|gif)/i;

  const CREDIT_PACKAGES = {
    basic: { credits: 50, price: 249 },
    pro:   { credits: 150, price: 699 },
    max:   { credits: 250, price: 1099 },
  };

  const app = express();
  const PORT = process.env.PORT || 3000;
  const SECRET_KEY = process.env.JWT_SECRET;

  app.set('trust proxy', 1);
  app.use(helmet());
  app.use(hpp());
  app.use(cors({ 
    origin: "*", 
    methods: ["GET", "POST"], 
    allowedHeaders: ["Content-Type", "Authorization", "stripe-signature"] 
  }));

  const globalLimiter = rateLimit({
    windowMs: 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    store: new RedisStore({
      sendCommand: (...args) => redisClient.sendCommand(args),
    }),
    handler: (req, res) => res.status(429).json({ message: "Troppe richieste globali" })
  });
  app.use(globalLimiter);

  function encrypt(text) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ALGO, ENC_KEY, iv);
    const encrypted = Buffer.concat([
      cipher.update(text, "utf8"),
      cipher.final()
    ]);
    const tag = cipher.getAuthTag();
    return `${iv.toString("base64")}:${tag.toString("base64")}:${encrypted.toString("base64")}`;
  }

  function decrypt(payload) {
    try {
      const [ivB64, tagB64, dataB64] = payload.split(":");
      if (!ivB64 || !tagB64 || !dataB64) return payload;
      const iv = Buffer.from(ivB64, "base64");
      const tag = Buffer.from(tagB64, "base64");
      const encrypted = Buffer.from(dataB64, "base64");
      const decipher = crypto.createDecipheriv(ALGO, ENC_KEY, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ]).toString("utf8");
    } catch {
      return payload;
    }
  }

  app.post(
    "/stripe-webhook",
    express.raw({ type: "application/json", limit: '50kb' }),
    async (req, res) => {
      const sig = req.headers["stripe-signature"];
      let event;
      try {
        event = stripe.webhooks.constructEvent(
          req.body,
          sig,
          process.env.STRIPE_WEBHOOK_SECRET
        );
      } catch (err) {
        return res.status(400).send(`Webhook Error`);
      }
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const { userEmail, type } = session.metadata || {};
        if (type === "PREMIUM_YEARLY" && userEmail) {
          const now = new Date();
          const user = await User.findOne({ schoolEmail: userEmail });
          if (user) {
            const baseDate = user.premiumUntil && user.premiumUntil > now ? user.premiumUntil : now;
            const newPremiumUntil = new Date(baseDate);
            newPremiumUntil.setFullYear(newPremiumUntil.getFullYear() + 1);
            await User.updateOne(
              { schoolEmail: userEmail },
              { premiumUntil: newPremiumUntil }
            );
          }
        }
      }
      res.json({ received: true });
    }
  );

  app.use(express.json({ limit: '10kb' }));

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

  const postLimiterIP = rateLimit({
    windowMs: 1000,
    max: 2,
    store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) }),
    keyGenerator: (req) => req.ip,
    handler: (req, res) => res.status(429).json({ message: "Limite richieste superato" })
  });

  const postLimiterUser = rateLimit({
    windowMs: 1000,
    max: 2,
    store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) }),
    keyGenerator: (req) => req.user?.schoolEmail || req.ip,
    handler: (req, res) => res.status(429).json({ message: "Limite richieste superato" })
  });

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
    premiumUntil: { type: Date, default: null }
  });

  userSchema.pre("save", function (next) {
    if (this.isModified("firstName")) this.firstName = encrypt(this.firstName);
    if (this.isModified("lastName")) this.lastName = encrypt(this.lastName);
    if (this.isModified("instagram") && this.instagram) this.instagram = encrypt(this.instagram);
    next();
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
    type: { type: String, enum: ["info","alert"], default: "info" }, 
    createdAt: { type: Date, default: Date.now }, 
    createdBy: String, 
    notified: { type: Boolean, default: false }
  });
  const Info = mongoose.model("Info", infoSchema);

  const bookSchema = new mongoose.Schema({ 
    title: { type: String, required: true }, 
    condition: { type: String }, 
    price: { type: Number, required: true }, 
    subject: { type: String }, 
    grade: { type: String }, 
    images: [String], 
    likes: { type: Number, default: 0 }, 
    likedBy: { type: [String], default: [] },
    createdAt: { type: Date, default: Date.now }, 
    createdBy: String, 
    description: { type: String, maxlength: 1000 }, 
    isbn: { type: String }
  });
  const Book = mongoose.model("Book", bookSchema);

  const fcmTokenSchema = new mongoose.Schema({
    schoolEmail: { type: String, required: true, index: true },
    token: { type: String, required: true, unique: true },
    updatedAt: { type: Date, default: Date.now }
  });
  const FcmToken = mongoose.model("FcmToken", fcmTokenSchema);

  const reviewSchema = new mongoose.Schema({
    reviewer: { type: String, required: true },
    seller: { type: String, required: true },
    rating: { type: Number, min: 1, max: 5, required: true },
    comment: { type: String, maxlength: 500 },
    createdAt: { type: Date, default: Date.now },
    isAutomatic: { type: Boolean, default: false }
  });
  reviewSchema.index({ reviewer: 1, seller: 1 });
  const Review = mongoose.model("Review", reviewSchema);

  const chatSchema = new mongoose.Schema({
    seller: { type: String, required: true, index: true },
    buyer: { type: String, required: true, index: true },
    bookId: { type: mongoose.Schema.Types.ObjectId, ref: "Book", required: true },
    lastMessage: { text: String, sender: String, createdAt: Date, seen: { type: Boolean, default: false } },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
  });
  chatSchema.index({ seller: 1, buyer: 1, bookId: 1 }, { unique: true, partialFilterExpression: { bookId: { $type: "objectId" } } });
  const Chat = mongoose.model("Chat", chatSchema);

  const messageSchema = new mongoose.Schema({
    chatId: { type: mongoose.Schema.Types.ObjectId, ref: "Chat", required: true, index: true },
    sender: { type: String, required: true },
    notified: { type: Boolean, default: false },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  });
  const Message = mongoose.model("Message", messageSchema);

  const myCache = new NodeCache({ stdTTL: 600, checkperiod: 120 });

  function cacheRequest(ttl = 600) {
    return (req, res, next) => {
      const key = `__cache__${req.user?.schoolEmail || 'guest'}${req.originalUrl}${JSON.stringify(req.query || {})}`;
      const cachedData = myCache.get(key);
      if (cachedData) return res.json(cachedData);
      const originalJson = res.json.bind(res);
      res.json = (body) => {
        if (res.statusCode >= 200 && res.statusCode < 300) myCache.set(key, body, ttl);
        originalJson(body);
      };
      next();
    };
  }

  function clearInfoCache() { 
    const keys = myCache.keys();
    const targets = keys.filter(key => key.includes("/get-info"));
    if (targets.length > 0) myCache.del(targets);
  }

  function clearBookCache() { 
    const keys = myCache.keys();
    const targets = keys.filter(key => key.includes("/get-books"));
    if (targets.length > 0) myCache.del(targets);
  }

  function clearReviewCache(seller) { 
    const keys = myCache.keys();
    const targets = keys.filter(key => key.includes(`/reviews/${seller}`));
    if (targets.length > 0) myCache.del(targets);
  }

  const createLimiter = (max) => rateLimit({ 
    windowMs: 60000, 
    max, 
    store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) }),
    standardHeaders: true, 
    legacyHeaders: false 
  });
  const authLimiter = createLimiter(30);

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
      if (!req.user.isAdmin) return res.status(403).json({ message: "Non sei admin" });
      next();
    });
  }

  async function checkNudity(urlToCheck) {
    try {
      const response = await fetch("https://jigsawstack.com/api/v1/validate/nsfw", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: urlToCheck })
      });
      const data = await response.json();
      return data;
    } catch (e) {
      return { nsfw: false, nudity: false };
    }
  }

  function generateCode(){ const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; let c=""; for(let i=0;i<6;i++) c+=chars[Math.floor(Math.random()*chars.length)]; return c; }
  function isValidSchoolEmail(email){ email=email.normalize("NFKC").replace(/[^\x00-\x7F]/g,"").toLowerCase().trim(); if(/[\r\n]/.test(email)) return false; return /^[^@]+@studenti\.liceocornaro\.edu\.it$/.test(email); }

  app.post("/register/request", postLimiterIP, async (req,res)=>{
    const { schoolEmail } = req.body;
    if(!schoolEmail) return res.status(400).json({ message: "Email richiesta" });
    if(!isValidSchoolEmail(schoolEmail)) return res.status(400).json({ message: "Email non valida" });
    const existingUser = await User.findOne({ schoolEmail });
    if (existingUser && existingUser.active) return res.status(400).json({ message: "Utente già registrato" });
    const now = Date.now();
    if(emailCooldown.has(schoolEmail) && now-emailCooldown.get(schoolEmail)<60000) return res.status(429).json({ message: "Attendi 60 secondi" });
    const code = generateCode();
    const expiresAt = new Date(now+10*60000);
    try{ 
      await sendEmailViaBridge({
        to: schoolEmail,
        subject: "Codice di verifica App Cornaro",
        html: `<div style="font-family: Arial, sans-serif; background-color: #f6f6f6; padding: 30px;"><div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.1);"><p>Per completare la registrazione, inserisci il codice di verifica qui sotto:</p><div style="text-align: center; margin: 20px 0; padding: 15px; background-color: #f0f0f0; border-radius: 6px; font-size: 24px; font-weight: bold; letter-spacing: 2px;">${code}</div><p>Non condividere questo codice con nessuno.</p></div></div>`
      });
    } catch(e){ return res.status(400).json({ message:"Email inesistente o problema nell'invio" }); }
    await VerificationCode.findOneAndUpdate({ schoolEmail }, { code, expiresAt }, { upsert:true });
    emailCooldown.set(schoolEmail, now);
    res.json({ message: "Codice inviato" });
  });

  app.post("/register/verify", postLimiterIP, authLimiter, async (req, res) => {
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
        return res.status(429).json({ message: "Troppi tentativi" });
      }
      failedAttempts.set(key, fail);
      return res.status(400).json({ message: "Codice non valido" });
    }
    if (record.expiresAt < new Date()) return res.status(400).json({ message: "Codice scaduto" });
    let validProfileImage = "";
    if (profileImage) {
      try {
        const imageUrlRegex = /(https?:\/\/[^\s]+?\.(?:png|jpg|jpeg|gif|webp))/gi;
        const urls = profileImage.match(imageUrlRegex);
        if (!urls) throw new Error("URL immagine non valido");
        const nudityCheck = await checkNudity(urls[0]);
        if (nudityCheck.nsfw || nudityCheck.nudity) throw new Error("Immagine non consentita");
        validProfileImage = urls[0];
      } catch (e) { return res.status(400).json({ message: e.message }); }
    }
    const hashed = await bcrypt.hash(password, 10);
    const existingUser = await User.findOne({ schoolEmail });
    if (existingUser && existingUser.active) return res.status(400).json({ message: "Utente già esistente" });
    if (existingUser && !existingUser.active) {
      await User.updateOne({ _id: existingUser._id }, { firstName, lastName, instagram: instagram || "", password: hashed, profileImage: validProfileImage, active: true });
      await VerificationCode.deleteOne({ schoolEmail });
      failedAttempts.set(key, { count: 0, lock: 0 });
      const token = jwt.sign({ id: schoolEmail }, SECRET_KEY);
      return res.status(201).json({ message: "Account riattivato", token });
    }
    await User.create({ firstName, lastName, instagram: instagram || "", schoolEmail, password: hashed, profileImage: validProfileImage });
    await VerificationCode.deleteOne({ schoolEmail });
    failedAttempts.set(key, { count: 0, lock: 0 });
    const token = jwt.sign({ id: schoolEmail }, SECRET_KEY);
    res.status(201).json({ message: "Registrazione completata", token });
  });

  app.post("/login", postLimiterIP, authLimiter, async (req,res)=>{
    const { schoolEmail,password }=req.body;
    if(!schoolEmail||!password) return res.status(400).json({ message:"Campi mancanti" });
    const key=schoolEmail;
    const fail=failedAttempts.get(key)||{ count:0, lock:0 };
    if(fail.lock>Date.now()) return res.status(429).json({ message:"Bloccato temporaneamente" });
    const user = await User.findOne({ schoolEmail, active: true });
    if(!user) { fail.count++; failedAttempts.set(key,fail); return res.status(400).json({ message:"Credenziali errate" }); }
    const match = await bcrypt.compare(password,user.password);
    if(!match) { fail.count++; failedAttempts.set(key,fail); return res.status(400).json({ message:"Credenziali errate" }); }
    failedAttempts.set(key, { count: 0, lock: 0 });
    const token = jwt.sign({ id: schoolEmail }, SECRET_KEY);
    res.json({ token, firstName: decrypt(user.firstName), lastName: decrypt(user.lastName), instagram: user.instagram ? decrypt(user.instagram) : "", schoolEmail: user.schoolEmail, profileImage: user.profileImage || "" });
  });

  app.post("/admin/clean-codes", verifyAdmin, async (req,res)=>{ const result=await VerificationCode.deleteMany({ expiresAt:{ $lt:new Date() } }); res.json({ eliminati:result.deletedCount }); });

  const storage = multer.memoryStorage();
  const upload = multer({ storage, limits:{ fileSize:2*1024*1024 } });

  app.post("/upload-imgur", postLimiterIP, upload.single("image"), async (req,res)=>{
    if(!req.file) return res.status(400).json({ message:"File mancante" });
    try{
      const boundary="----WebKitFormBoundaryCheckNSFW";
      const body=Buffer.concat([Buffer.from(`--${boundary}\r\n`),Buffer.from(`Content-Disposition: form-data; name="nudepic"; filename="${req.file.originalname}"\r\n`),Buffer.from(`Content-Type: ${req.file.mimetype}\r\n\r\n`),req.file.buffer,Buffer.from(`\r\n--${boundary}--\r\n`)]);
      const nsfwResponse=await fetch("https://letspurify.askjitendra.com/send/data",{ method:"POST", headers:{"content-type":`multipart/form-data; boundary=${boundary}`}, body });
      const nsfwData=await nsfwResponse.json();
      if(nsfwData.status) return res.status(400).json({ message:"L'immagine non è consentita" });
      const base64Image=req.file.buffer.toString("base64");
      const imgurResponse=await fetch("https://api.imgur.com/3/upload",{ method:"POST", headers:{ Authorization:`Client-ID ${process.env.IMGUR_CLIENT_ID}` }, body:new URLSearchParams({ image:base64Image }) });
      const imgurData=await imgurResponse.json();
      if(imgurData.success) res.json({ link:imgurData.data.link });
      else res.status(500).json({ message:"Errore caricamento Imgur" });
    } catch(e){ res.status(500).json({ message:e.message }); }
  });

  app.post("/add-info", verifyAdmin, async (req,res)=>{
    const { title,message,type }=req.body;
    if(!title||!message) return res.status(400).json({ message:"Campi mancanti" });
    const info = await Info.create({ title,message,type:type||"info",createdBy:req.user.schoolEmail });
    clearInfoCache();
    res.status(201).json({ info });
  });

  app.post("/delete-info", verifyAdmin, async (req,res)=>{
    if(!req.body.id) return res.status(400).json({ message:"ID mancante" });
    const deleted=await Info.findByIdAndDelete(req.body.id);
    if(!deleted) return res.status(404).json({ message:"Post non trovato" });
    clearInfoCache();
    res.json({ message:"Post eliminato" });
  });

  app.get("/get-info", cacheRequest(10), async (req,res)=>{
    let page=parseInt(req.query.page)||1;
    const limit=15;
    const skip=(page-1)*limit;
    const infos = await Info.find({}, { createdBy:0 }).sort({ createdAt:-1 }).skip(skip).limit(limit);
    const total = await Info.countDocuments();
    res.json({ infos,total,page,totalPages:Math.ceil(total/limit) });
  });

  app.get("/is-admin", verifyUser, async (req,res)=> res.json({ isAdmin:req.user.isAdmin }));

  app.get("/get-books", verifyUser, cacheRequest(10), async (req, res) => {
    try {
      const { condition, subject, grade, search, minPrice, maxPrice, page, limit, createdBy } = req.query;
      const currentPage = Math.max(parseInt(page) || 1, 1);
      const booksLimit = Math.max(parseInt(limit) || 16, 1);
      const skip = (currentPage - 1) * booksLimit;
      let query = {};
      const activeUsers = await User.find({ active: true }).select("schoolEmail");
      query.createdBy = { $in: activeUsers.map(u => u.schoolEmail) };
      if (condition && condition !== "Tutte") query.condition = condition;
      if (subject && subject !== "Tutte") query.subject = subject;
      if (grade && grade !== "Tutte") query.grade = grade;
      if (createdBy) query.createdBy = createdBy;
      if (search) query.$or = [{ title: { $regex: search, $options: "i" } }, { subject: { $regex: search, $options: "i" } }];
      if (minPrice || maxPrice) {
        query.price = {};
        if (minPrice) query.price.$gte = Number(minPrice);
        if (maxPrice) query.price.$lte = Number(maxPrice);
      }
      const [books, total] = await Promise.all([
        Book.find(query).sort({ createdAt: -1 }).skip(skip).limit(booksLimit).lean(),
        Book.countDocuments(query)
      ]);
      const booksWithLikes = books.map(book => ({
        ...book,
        likedByMe: book.likedBy.includes(req.user.schoolEmail),
        createdByMe: book.createdBy === req.user.schoolEmail
      }));
      res.json({ books: booksWithLikes, total, page: currentPage, totalPages: Math.ceil(total / booksLimit) });
    } catch (e) { res.status(500).json({ message: "Errore caricamento libri" }); }
  });

  app.post("/delete-book", verifyUser, async (req, res) => {
    try {
      if (!req.body.bookId) return res.status(400).json({ message: "bookId mancante" });
      const book = await Book.findById(req.body.bookId);
      if (!book) return res.status(404).json({ message: "Libro non trovato" });
      if (book.createdBy !== req.user.schoolEmail) return res.status(403).json({ message: "Non autorizzato" });
      await Book.findByIdAndDelete(req.body.bookId);
      clearBookCache();
      res.status(200).json({ message: "Libro eliminato" });
    } catch (error) { res.status(500).json({ message: "Errore server" }); }
  });

  app.post("/add-books", verifyUser, postLimiterUser, async (req, res) => {
    const { title, condition, price, subject, grade, images, description, isbn } = req.body;
    if (!title || !condition || !price || !subject || !grade || !images) return res.status(400).json({ message: "Dati mancanti" });
    try {
      for (const imgUrl of images) {
        const nudityCheck = await checkNudity(imgUrl);
        if (nudityCheck.nsfw || nudityCheck.nudity) return res.status(400).json({ message: "Immagine non consentita" });
      }
      const session = await mongoose.startSession();
      session.startTransaction();
      try {
        if (CREDITS_ENABLED) {
          const updatedUser = await User.findOneAndUpdate({ _id: req.user._id, credits: { $gte: 10 } }, { $inc: { credits: -10 } }, { session, new: true });
          if (!updatedUser) throw new Error("Crediti insufficienti");
        }
        const [newBook] = await Book.create([{ title, condition, price, subject, grade, images, description: description || "", isbn: isbn || "", createdBy: req.user.schoolEmail }], { session });
        await session.commitTransaction();
        session.endSession();
        clearBookCache();
        return res.status(201).json({ message: "Libro pubblicato", book: newBook });
      } catch (error) {
        await session.abortTransaction();
        session.endSession();
        return res.status(error.message === "Crediti insufficienti" ? 403 : 400).json({ message: error.message });
      }
    } catch (e) { res.status(500).json({ message: "Errore interno" }); }
  });

  app.post("/books/like", verifyUser, postLimiterUser, async (req, res) => {
    const { bookId } = req.body;
    if (!bookId) return res.status(400).json({ message: "bookId mancante" });
    try {
      const liked = await Book.findOneAndUpdate({ _id: bookId, likedBy: { $ne: req.user.schoolEmail } }, { $addToSet: { likedBy: req.user.schoolEmail }, $inc: { likes: 1 } }, { new: true });
      if (!liked) {
        const unliked = await Book.findOneAndUpdate({ _id: bookId, likedBy: req.user.schoolEmail }, { $pull: { likedBy: req.user.schoolEmail }, $inc: { likes: -1 } }, { new: true });
        clearBookCache();
        return res.json({ liked: false, likes: unliked.likes });
      }
      clearBookCache();
      res.json({ liked: true, likes: liked.likes });
    } catch (e) { res.status(500).json({ message: "Errore server" }); }
  });

  app.get("/profile/:email", verifyUser, cacheRequest(10), async (req, res) => {
    const user = await User.findOne({ schoolEmail: req.params.email, active: true }, { firstName: 1, lastName: 1, profileImage: 1, instagram: 1, isReliable: 1, averageRating: 1, ratingsCount: 1, lastSeenAt: 1 }).lean();
    if (!user) return res.status(404).json({ message: "Utente non trovato" });
    const isOnline = user.lastSeenAt && Date.now() - new Date(user.lastSeenAt).getTime() < 300000;
    res.json({ ...user, firstName: decrypt(user.firstName), lastName: decrypt(user.lastName), instagram: user.instagram ? decrypt(user.instagram) : "" });
  });

  app.get("/reviews/:seller", cacheRequest(10), async (req, res) => {
    const reviews = await Review.find({ seller: req.params.seller }).sort({ createdAt: -1 }).limit(50);
    res.json(reviews.map(r => ({ rating: r.rating, comment: r.comment, createdAt: r.createdAt, reviewerEmail: r.reviewer, isAutomatic: r.isAutomatic || false })));
  });

  app.post("/reviews/add", verifyUser, createLimiter(10), async (req, res) => {
    const { seller, rating, comment } = req.body;
    if (!seller || !rating || seller === req.user.schoolEmail) return res.status(400).json({ message: "Dati non validi" });
    try {
      if (!req.user.isAdmin) {
        const exists = await Review.findOne({ reviewer: req.user.schoolEmail, seller });
        if (exists) return res.status(400).json({ message: "Già recensito" });
      }
      await Review.create({ reviewer: req.user.schoolEmail, seller, rating, comment: comment || "", isAutomatic: req.user.isAdmin });
      const stats = await Review.aggregate([{ $match: { seller } }, { $group: { _id: null, avg: { $avg: "$rating" }, count: { $sum: 1 } } }]);
      await User.updateOne({ schoolEmail: seller }, { averageRating: stats[0].avg, ratingsCount: stats[0].count, isReliable: stats[0].avg >= 4 && stats[0].count >= 3 });
      clearReviewCache(seller);
      res.status(201).json({ message: "Recensione inviata" });
    } catch (e) { res.status(500).json({ message: "Errore server" }); }
  });

  app.post("/chats/start", verifyUser, async (req, res) => {
    const { sellerEmail, bookId } = req.body;
    if (!sellerEmail || !bookId || sellerEmail === req.user.schoolEmail) return res.status(400).json({ message: "Dati non validi" });
    let chat = await Chat.findOne({ seller: sellerEmail, buyer: req.user.schoolEmail, bookId });
    if (chat) return res.json({ chatId: chat._id });
    chat = await Chat.create({ seller: sellerEmail, buyer: req.user.schoolEmail, bookId });
    res.status(201).json({ chatId: chat._id });
  });

  app.get("/chats", verifyUser, async (req, res) => {
    const chats = await Chat.find({ $or: [{ seller: req.user.schoolEmail }, { buyer: req.user.schoolEmail }] }).sort({ updatedAt: -1 }).populate('bookId', 'title images price').lean();
    res.json(chats.map(chat => ({ _id: chat._id, other: chat.seller === req.user.schoolEmail ? chat.buyer : chat.seller, lastMessage: chat.lastMessage ? { ...chat.lastMessage, text: decrypt(chat.lastMessage.text) } : null, updatedAt: chat.updatedAt, book: chat.bookId ? { title: chat.bookId.title, image: chat.bookId.images[0], price: chat.bookId.price } : null })));
  });

  app.get("/chats/:chatId/messages", verifyUser, verifyChatAccess, async (req, res) => {
    const { limit = 20, skip = 0 } = req.query;
    const messages = await Message.find({ chatId: req.params.chatId }).sort({ createdAt: -1 }).skip(parseInt(skip)).limit(parseInt(limit)).lean();
    res.json(messages.map(msg => ({ _id: msg._id, sender: msg.sender, text: decrypt(msg.text), createdAt: msg.createdAt, isMe: msg.sender === req.user.schoolEmail })).reverse());
  });

  app.post("/chats/:chatId/messages", verifyUser, postLimiterUser, verifyChatAccess, async (req, res) => {
    const { text } = req.body;
    if (!text) return res.status(400).json({ message: "Testo mancante" });
    const match = text.match(IMGUR_REGEX);
    if (match) {
      const nudityCheck = await checkNudity(match[0]);
      if (nudityCheck.nsfw || nudityCheck.nudity) return res.status(400).json({ message: "Immagine non consentita" });
    }
    const encryptedText = encrypt(text);
    const msg = await Message.create({ chatId: req.params.chatId, sender: req.user.schoolEmail, text: encryptedText });
    await Chat.findByIdAndUpdate(req.params.chatId, { lastMessage: { text: encryptedText, sender: req.user.schoolEmail, createdAt: msg.createdAt, seen: false }, updatedAt: new Date() });
    res.status(201).json(msg);
  });

  app.post("/fcm/register", verifyUser, async (req, res) => {
    if (!req.body.token) return res.status(400).json({ message: "Token mancante" });
    await FcmToken.findOneAndUpdate({ token: req.body.token }, { schoolEmail: req.user.schoolEmail, updatedAt: new Date() }, { upsert: true });
    res.json({ message: "Token salvato" });
  });

  app.post("/user/notifications", verifyUser, async (req, res) => {
    const update = {};
    if (req.body.push !== undefined) update["notifications.push"] = !!req.body.push;
    if (req.body.email !== undefined) update["notifications.email"] = !!req.body.email;
    await User.updateOne({ schoolEmail: req.user.schoolEmail }, update);
    res.json({ message: "Preferenze aggiornate" });
  });

  app.post("/user/deactivate", verifyUser, async (req, res) => {
    if (!req.body.password) return res.status(400).json({ message: "Password richiesta" });
    const match = await bcrypt.compare(req.body.password, req.user.password);
    if (!match) return res.status(401).json({ message: "Password errata" });
    await User.updateOne({ _id: req.user._id }, { active: false });
    res.json({ message: "Account disattivato" });
  });

  app.get("/user/premium", verifyUser, (req, res) => {
    const isPremium = req.user.premiumUntil && req.user.premiumUntil > new Date();
    res.json({ premium: !!isPremium, premiumUntil: req.user.premiumUntil });
  });

  app.post("/premium/create-checkout", verifyUser, async (req, res) => {
    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        mode: "payment",
        line_items: [{ price_data: { currency: "eur", unit_amount: 199, product_data: { name: "Premium App Cornaro" } }, quantity: 1 }],
        success_url: `cornaro://premium-success`,
        cancel_url: `cornaro://premium-cancel`,
        metadata: { userEmail: req.user.schoolEmail, type: "PREMIUM_YEARLY" }
      });
      res.json({ url: session.url });
    } catch (e) { res.status(500).json({ message: "Errore checkout" }); }
  });

  async function sendEmailViaBridge({ to, subject, text, html }) {
    const res = await fetch(process.env.EMAIL_BRIDGE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${process.env.EMAIL_BRIDGE_SECRET}` },
      body: JSON.stringify({ to, subject, text, html })
    });
    if (!res.ok) throw new Error("Errore invio email");
  }

  setInterval(()=>{
    const now=Date.now();
    for(const [email,ts] of emailCooldown) if(now-ts>600000) emailCooldown.delete(email);
    for(const [email,data] of failedAttempts) if(data.lock<now) failedAttempts.delete(email);
  }, 300000);

  const server = app.listen(PORT);
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 66000;
}