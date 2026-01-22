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

const CREDIT_PACKAGES = {
  basic: { credits: 50, price: 249 },
  pro:   { credits: 150, price: 699 },
  max:   { credits: 250, price: 1099 },
};

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;

app.use(cors({ 
  origin: "*", 
  methods: ["GET", "POST"], 
  allowedHeaders: ["Content-Type", "Authorization", "stripe-signature"] 
}));

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, ENC_KEY, iv);

  const encrypted = Buffer.concat([
    cipher.update(text, "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  // formato: iv:tag:ciphertext (base64)
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

/* app.post("/stripe-webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body, 
      sig, 
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error(`Errore validazione Webhook: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const { userEmail, packageId } = session.metadata;
    const pkg = CREDIT_PACKAGES[packageId];

    if (pkg) {
      console.log(`Pagamento completato per ${userEmail}. Pacchetto: ${packageId}`);
      await User.updateOne(
        { schoolEmail: userEmail },
        { $inc: { credits: pkg.credits } }
      );
    }
  }

  res.json({ received: true });
}); */

app.use(express.json());

async function verifyUser(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token mancante" });

  try {
    const payload = jwt.verify(token, SECRET_KEY);
    const user = await User.findOne({ schoolEmail: payload.id });
    if (!user) return res.status(401).json({ message: "Utente non trovato" });

    const now = Date.now();
    const UPDATE_INTERVAL = 5 * 60 * 1000;

    if (
      !user.lastSeenUpdateAt ||
      now - user.lastSeenUpdateAt.getTime() > UPDATE_INTERVAL
    ) {
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
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    res.status(429).json({ message: "Limite richieste superato, riprova tra 1 secondo" });
  }
});

const postLimiterUser = rateLimit({
  windowMs: 1000,
  max: 2,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.schoolEmail || req.ip,
  handler: (req, res) => {
    res.status(429).json({ message: "Limite richieste superato, riprova tra 1 secondo" });
  }
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
  notifications: {
    push: { type: Boolean, default: true },
    email: { type: Boolean, default: true }
  }
});
userSchema.pre("save", function (next) {
  if (this.isModified("firstName")) {
    this.firstName = encrypt(this.firstName);
  }

  if (this.isModified("lastName")) {
    this.lastName = encrypt(this.lastName);
  }

  if (this.isModified("instagram") && this.instagram) {
    this.instagram = encrypt(this.instagram);
  }

  next();
});
const User = mongoose.model("User", userSchema);

const codeSchema = new mongoose.Schema({ 
  schoolEmail: { 
    type: String, 
    required: true 
  }, 
  code: String, 
  expiresAt: Date 
});
const VerificationCode = mongoose.model("VerificationCode", codeSchema);

const infoSchema = new mongoose.Schema({ 
  title: { 
    type: String, 
    required: true 
  }, 
  message: { 
    type: String, 
    required: true 
  }, 
  type: { 
    type: String, 
    enum: ["info","alert"], 
    default: "info" 
  }, 
  createdAt: { 
    type: Date, 
    default: Date.now 
  }, 
  createdBy: String, 
  notified: { 
    type: Boolean, 
    default: false 
  }
});
const Info = mongoose.model("Info", infoSchema);

const bookSchema = new mongoose.Schema({ 
  title: {
    type: String, 
    required: true 
  }, 
  condition: { 
    type: String 
  }, 
  price: { 
    type: Number,
    required: true 
  }, 
  subject: { 
    type: String 
  }, 
  grade: { 
    type: String 
  }, 
  images: [String], 
  likes: { 
    type: Number, 
    default: 0 
  }, 
  likedBy: { 
    type: [String], 
    default: [] 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }, 
  createdBy: String, 
  description: { 
    type: String, 
    maxlength: 1000 
  }, isbn: { 
    type: String 
  }
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
chatSchema.index(
  { seller: 1, buyer: 1, bookId: 1 },
  { unique: true, partialFilterExpression: { bookId: { $type: "objectId" } } }
);
const Chat = mongoose.model("Chat", chatSchema);

const messageSchema = new mongoose.Schema({
  chatId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Chat",
    required: true,
    index: true
  },
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
    if (cachedData) {
      return res.json(cachedData);
    }
    const originalJson = res.json.bind(res);
    res.json = (body) => {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        myCache.set(key, body, ttl);
      }
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

const createLimiter = (max) => rateLimit({ windowMs: 60000, max, standardHeaders: true, legacyHeaders: false });
const authLimiter = createLimiter(30);

const transporter = nodemailer.createTransport({ service: "gmail", auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } });

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

async function checkNudity(urlToCheck) {
  try {
    const response = await fetch("https://jigsawstack.com/api/v1/validate/nsfw", {
      method: "POST",
      headers: {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "origin": "https://jigsawstack.com",
        "referer": "https://jigsawstack.com/nsfw-detection",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
      },
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
  if(await User.findOne({ schoolEmail })) return res.status(400).json({ message: "Utente già registrato" });
  const now = Date.now();
  if(emailCooldown.has(schoolEmail) && now-emailCooldown.get(schoolEmail)<60000) return res.status(429).json({ message: "Attendi 60 secondi" });
  const code = generateCode();
  const expiresAt = new Date(now+10*60000);
  try{ 
    await sendEmailViaBridge({
      to: schoolEmail,
      subject: "Codice di verifica App Cornaro",
      html: `
        <div style="font-family: Arial, sans-serif; background-color: #f6f6f6; padding: 30px;">
          <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.1);">
            <p>Per completare la registrazione, inserisci il codice di verifica qui sotto:</p>
            <div style="text-align: center; margin: 20px 0; padding: 15px; background-color: #f0f0f0; border-radius: 6px; font-size: 24px; font-weight: bold; letter-spacing: 2px;">
              ${code}
            </div>
            <p>Non condividere questo codice con nessuno. Se non hai richiesto questo codice, puoi ignorare questa email.</p>
          </div>
        </div>
      `
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
      return res.status(429).json({ message: "Troppi tentativi, riprova tra 10 minuti" });
    }
    failedAttempts.set(key, fail);
    return res.status(400).json({ message: "Codice non valido" });
  }

  if (record.expiresAt < new Date()) return res.status(400).json({ message: "Codice scaduto" });
  if (await User.findOne({ schoolEmail })) return res.status(400).json({ message: "Utente già esistente" });

  let validProfileImage = "";
  if (profileImage) {
    try {
      const imageUrlRegex = /(https?:\/\/[^\s]+?\.(?:png|jpg|jpeg|gif|webp))/gi;
      const urls = profileImage.match(imageUrlRegex);
      if (!urls || urls.length === 0) throw new Error("URL immagine non valido");
      const imageUrl = urls[0];
      const nudityCheck = await checkNudity(imageUrl);
      if (nudityCheck.nsfw || nudityCheck.nudity) throw new Error("L'immagine contiene contenuti non consentiti");
      validProfileImage = imageUrl;
    } catch (e) {
      return res.status(400).json({ message: e.message });
    }
  }

  const hashed = await bcrypt.hash(password, 10);
  await User.create({ firstName, lastName, instagram: instagram || "", schoolEmail, password: hashed, profileImage: validProfileImage });
  await VerificationCode.deleteOne({ schoolEmail });
  failedAttempts.delete(key);
  const token = jwt.sign({ id: schoolEmail }, SECRET_KEY);
  res.status(201).json({ message: "Registrazione completata", token });
});

app.post("/login", postLimiterIP, authLimiter, async (req,res)=>{
  const { schoolEmail,password }=req.body;
  if(!schoolEmail||!password) return res.status(400).json({ message:"Campi mancanti" });
  const key=schoolEmail;
  const fail=failedAttempts.get(key)||{ count:0, lock:0 };
  if(fail.lock>Date.now()) return res.status(429).json({ message:"Bloccato temporaneamente" });
  const user = await User.findOne({ schoolEmail });
  if(!user) { fail.count++; failedAttempts.set(key,fail); return res.status(400).json({ message:"Credenziali errate" }); }
  const match = await bcrypt.compare(password,user.password);
  if(!match) { fail.count++; failedAttempts.set(key,fail); return res.status(400).json({ message:"Credenziali errate" }); }
  failedAttempts.delete(key);
  const token = jwt.sign({ id: schoolEmail }, SECRET_KEY);
  res.json({ 
    message:"Login riuscito", 
    token, 
    firstName: decrypt(user.firstName), 
    lastName: decrypt(user.lastName), 
    instagram: user.instagram ? decrypt(user.instagram) : "", 
    schoolEmail: user.schoolEmail, 
    profileImage: user.profileImage || "" 
  });
});

app.post("/admin/clean-codes", verifyAdmin, async (req,res)=>{ const result=await VerificationCode.deleteMany({ expiresAt:{ $lt:new Date() } }); res.json({ eliminati:result.deletedCount }); });

const storage = multer.memoryStorage();
const upload = multer({ storage, limits:{ fileSize:2*1024*1024 } });

app.post("/upload-imgur", postLimiterIP, upload.single("image"), async (req,res)=>{
  if(!req.file) return res.status(400).json({ message:"File mancante" });
  try{
    const fetch=(await import("node-fetch")).default;
    const boundary="----WebKitFormBoundaryCheckNSFW";
    const body=Buffer.concat([Buffer.from(`--${boundary}\r\n`),Buffer.from(`Content-Disposition: form-data; name="nudepic"; filename="${req.file.originalname}"\r\n`),Buffer.from(`Content-Type: ${req.file.mimetype}\r\n\r\n`),req.file.buffer,Buffer.from(`\r\n--${boundary}--\r\n`)]);
    const nsfwResponse=await fetch("https://letspurify.askjitendra.com/send/data",{ method:"POST", headers:{"accept":"*/*","content-type":`multipart/form-data; boundary=${boundary}`}, body });
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
  res.status(201).json({ message:"Avviso aggiunto", info });
});

app.post("/delete-info", verifyAdmin, async (req,res)=>{
  const { id }=req.body;
  if(!id) return res.status(400).json({ message:"ID mancante" });
  const deleted=await Info.findByIdAndDelete(id);
  if(!deleted) return res.status(404).json({ message:"Post non trovato" });
  clearInfoCache();
  res.json({ message:"Post eliminato", deleted });
});

app.post("/update-info", verifyAdmin, async (req,res)=>{
  const { id, title, message, type } = req.body;
  if(!id||!title||!message||!type) return res.status(400).json({ message:"Campi mancanti" });
  const updated = await Info.findByIdAndUpdate(id,{ title,message,type },{ new:true });
  if(!updated) return res.status(404).json({ message:"Post non trovato" });
  clearInfoCache();
  res.json({ message:"Avviso aggiornato", info:updated });
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
    if (condition && condition !== "Tutte") query.condition = condition;
    if (subject && subject !== "Tutte") query.subject = subject;
    if (grade && grade !== "Tutte") query.grade = grade;
    if (createdBy) query.createdBy = createdBy;
    if (search) query.$or = [
      { title: { $regex: search, $options: "i" } },
      { subject: { $regex: search, $options: "i" } }
    ];
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
      _id: book._id,
      title: book.title,
      condition: book.condition,
      price: book.price,
      subject: book.subject,
      grade: book.grade,
      images: book.images,
      likes: book.likes,
      likedByMe: book.likedBy.includes(req.user.schoolEmail),
      createdBy: book.createdBy,
      createdAt: book.createdAt,
      description: book.description || "",
      isbn: book.isbn || "",  
    }));
    res.json({ books: booksWithLikes, total, page: currentPage, totalPages: Math.ceil(total / booksLimit) });
  } catch (e) {
    res.status(500).json({ message: "Errore caricamento libri" });
  }
});

app.get("/get-favorite-books", verifyUser, async (req, res) => {
  try {
    const books = await Book.find({
      likedBy: req.user.schoolEmail
    }).sort({ createdAt: -1 }).lean();

    const result = books.map(book => ({
      _id: book._id,
      title: book.title,
      condition: book.condition,
      price: book.price,
      subject: book.subject,
      grade: book.grade,
      images: book.images,
      likes: book.likes,
      likedByMe: true,
      createdBy: book.createdBy,
      createdAt: book.createdAt,
      description: book.description || "",
      isbn: book.isbn || ""
    }));

    res.json({ books: result });
  } catch (e) {
    res.status(500).json({ message: "Errore caricamento preferiti" });
  }
});

app.post("/add-books", verifyUser, postLimiterUser, async (req, res) => {
  const { title, condition, price, subject, grade, images, description, isbn } = req.body;
  if (!title || !condition || !price || !subject || !grade || !images)
    return res.status(400).json({ message: "Campi obbligatori mancanti" });
  if (!Array.isArray(images) || images.length === 0)
    return res.status(400).json({ message: "Immagini non valide" });

  try {
    for (const imgUrl of images) {
      const nudityCheck = await checkNudity(imgUrl);
      if (nudityCheck.nsfw || nudityCheck.nudity) {
        return res.status(400).json({ message: "Immagini non consentite" });
      }
    }

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      let updatedUser = req.user;

      if (CREDITS_ENABLED) {
        updatedUser = await User.findOneAndUpdate(
          { _id: req.user._id, credits: { $gte: 10 } },
          { $inc: { credits: -10 } },
          { session, new: true }
        );
        if (!updatedUser) throw new Error("Crediti insufficienti");
      }

      const [newBook] = await Book.create([{
        title,
        condition,
        price,
        subject,
        grade,
        images,
        description: description || "",
        isbn: isbn || "",
        createdBy: req.user.schoolEmail
      }], { session });

      await session.commitTransaction();
      session.endSession();
      clearBookCache();
      return res.status(201).json({
        message: "Libro pubblicato",
        creditsLeft: CREDITS_ENABLED ? updatedUser.credits : null,
        book: newBook
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      return res.status(error.message === "Crediti insufficienti" ? 403 : 400).json({ message: error.message });
    }
  } catch (e) {
    res.status(500).json({ message: "Errore interno del server" });
  }
});

app.post("/books/like", verifyUser, postLimiterUser, async (req, res) => {
  const { bookId } = req.body;
  const userEmail = req.user.schoolEmail;
  if (!bookId) return res.status(400).json({ message: "bookId mancante" });

  try {
    const liked = await Book.findOneAndUpdate(
      { _id: bookId, likedBy: { $ne: userEmail } },
      { $addToSet: { likedBy: userEmail }, $inc: { likes: 1 } },
      { new: true }
    );

    if (!liked) {
      const unliked = await Book.findOneAndUpdate(
        { _id: bookId, likedBy: userEmail },
        { $pull: { likedBy: userEmail }, $inc: { likes: -1 } },
        { new: true }
      );
      clearBookCache();
      return res.json({ liked: false, likes: unliked.likes });
    }

    clearBookCache();
    res.json({ liked: true, likes: liked.likes });
  } catch (e) {
    res.status(500).json({ message: "Errore server" });
  }
});

app.get("/profile/:email", verifyUser, cacheRequest(10), async (req, res) => {
  const email = req.params.email;
  const user = await User.findOne(
    { schoolEmail: email },
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

app.get("/reviews/:seller", cacheRequest(10), async (req, res) => {
  const seller = req.params.seller;
  const reviews = await Review.find(
    { seller },
    { reviewer: 1, rating: 1, comment: 1, createdAt: 1, isAutomatic: 1 }
  ).sort({ createdAt: -1 }).limit(50);
  const reviewsWithProfile = reviews.map(r => ({
    rating: r.rating,
    comment: r.comment,
    createdAt: r.createdAt,
    reviewerEmail: r.reviewer,
    isAutomatic: r.isAutomatic !== undefined ? r.isAutomatic : false,
  }));
  res.json(reviewsWithProfile);
});

const reviewLimiter = createLimiter(10);

app.post("/reviews/add", verifyUser, reviewLimiter, async (req, res) => {
  const { seller, rating, comment } = req.body;
  if (!seller || !rating) return res.status(400).json({ message: "Dati mancanti" });
  if (!isValidSchoolEmail(seller)) return res.status(400).json({ message: "Email venditore non valida" });
  if (seller === req.user.schoolEmail) return res.status(400).json({ message: "Non puoi recensire te stesso" });
  if (rating < 1 || rating > 5) return res.status(400).json({ message: "Rating non valido" });

  const sellerUser = await User.findOne({ schoolEmail: seller });
  if (!sellerUser) return res.status(404).json({ message: "Venditore inesistente" });

  try {
    if (!req.user.isAdmin) {
      const exists = await Review.findOne({ reviewer: req.user.schoolEmail, seller });
      if (exists) return res.status(400).json({ message: "Hai già recensito questo venditore" });
    }
    await Review.create({ reviewer: req.user.schoolEmail, seller, rating, comment: comment || "", isAutomatic: req.user.isAdmin });
    const stats = await Review.aggregate([
      { $match: { seller } },
      { $group: { _id: null, avg: { $avg: "$rating" }, count: { $sum: 1 } } }
    ]);
    const avg = stats.length ? stats[0].avg : 0;
    const count = stats.length ? stats[0].count : 0;
    await User.updateOne({ schoolEmail: seller }, { averageRating: avg, ratingsCount: count, isReliable: avg >= 4 && count >= 3 });
    clearReviewCache(seller);
    const profileKeys = myCache.keys().filter(k => k.includes(`/profile/${seller}`));
    if (profileKeys.length > 0) myCache.del(profileKeys);
    res.status(201).json({ message: "Recensione inviata" });
  } catch (e) {
    res.status(500).json({ message: "Errore server" });
  }
});

app.post("/chats/start", verifyUser, async (req, res) => {
  const { sellerEmail, bookId } = req.body;
  if (!sellerEmail || !bookId) return res.status(400).json({ message: "Dati mancanti" });
  if (sellerEmail === req.user.schoolEmail) return res.status(400).json({ message: "Non puoi scrivere a te stesso" });
  let chat = await Chat.findOne({ seller: sellerEmail, buyer: req.user.schoolEmail, bookId });
  if (chat) return res.status(200).json({ message: "Chat già esistente", chatId: chat._id });
  chat = await Chat.create({ seller: sellerEmail, buyer: req.user.schoolEmail, bookId });
  try {
    const sellerUser = await User.findOne({ schoolEmail: sellerEmail });
    const buyerUser = req.user;
    const book = await Book.findById(bookId);
    if (sellerUser && book && sellerUser.notifications.email) {
      await sendEmailViaBridge({
        to: sellerUser.schoolEmail,
        subject: "Hai una nuova chat su App Cornaro",
        html: `
          <div style="font-family: Arial, sans-serif; background:#f6f6f6; padding:30px;">
            <div style="max-width:600px; margin:auto; background:#fff; padding:20px; border-radius:8px;">
              <h2>Nuovo messaggio ricevuto</h2>
              <p><strong>${buyerUser.firstName} ${buyerUser.lastName}</strong> ha iniziato una chat per il libro:</p>
              <p style="font-size:18px; font-weight:bold;">${book.title}</p>
              <p>Apri l’app per rispondere al messaggio.</p>
            </div>
          </div>
        `
      });
    }
  } catch (e) {}
  res.status(201).json({ message: "Chat creata", chatId: chat._id });
});

app.get("/chats", verifyUser, async (req, res) => {
  const chats = await Chat.find({ $or: [ { seller: req.user.schoolEmail }, { buyer: req.user.schoolEmail } ] })
    .sort({ updatedAt: -1 }).populate('bookId', 'title images price').lean();
  const mappedChats = chats.map(chat => {
    const me = req.user.schoolEmail;
    const other = chat.seller === me ? chat.buyer : chat.seller;
    const bookInfo = chat.bookId ? { title: chat.bookId.title, image: chat.bookId.images[0] || null, price: chat.bookId.price } : null;
    return { _id: chat._id, me, other, lastMessage: chat.lastMessage ? { ...chat.lastMessage, text: decrypt(chat.lastMessage.text) } : null, updatedAt: chat.updatedAt, book: bookInfo };
  });
  res.json(mappedChats);
});

app.get("/chats/:chatId/messages", verifyUser, verifyChatAccess, async (req, res) => {
  const { limit = 20, skip = 0 } = req.query;
  if (req.chat.lastMessage && req.chat.lastMessage.sender !== req.user.schoolEmail && req.chat.lastMessage.seen === false) {
    await Chat.updateOne({ _id: req.chat._id }, { $set: { "lastMessage.seen": true } });
  }
  const messages = await Message.find({ chatId: req.params.chatId }).sort({ createdAt: -1 }).skip(parseInt(skip)).limit(parseInt(limit)).lean();
  const mapped = messages.map(msg => ({
    _id: msg._id,
    sender: msg.sender,
    text: decrypt(msg.text),
    createdAt: msg.createdAt,
    isMe: msg.sender === req.user.schoolEmail
  }));
  res.json(mapped.reverse());
});

app.post("/chats/:chatId/messages", verifyUser, postLimiterUser, verifyChatAccess, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ message: "Testo mancante" });

  const encryptedText = encrypt(text);

  const msg = await Message.create({ 
    chatId: req.params.chatId, 
    sender: req.user.schoolEmail, 
    text: encryptedText
  });

  await Chat.findByIdAndUpdate(req.params.chatId, { 
    lastMessage: { 
      text: encryptedText,
      sender: req.user.schoolEmail, 
      createdAt: msg.createdAt, 
      seen: false 
    },
    updatedAt: new Date() 
  });

  setImmediate(async () => {
    try {
      const chat = req.chat;
      const receiverEmail = chat.seller === req.user.schoolEmail ? chat.buyer : chat.seller;
      
      const receiverUser = await User.findOne({ schoolEmail: receiverEmail });
      if (!receiverUser || !receiverUser.notifications.push) {
        await Message.updateOne({ _id: msg._id }, { notified: true });
        return;
      }

      const receiverTokens = await FcmToken.find({ schoolEmail: receiverEmail });
      
      if (receiverTokens.length > 0) {
        const payload = { 
          notification: { 
            title: `${req.user.firstName} ${req.user.lastName}`, 
            body: text.length > 80 ? text.slice(0, 80) + "..." : text 
          }, 
          data: { 
            chatId: req.params.chatId.toString(), 
            type: "NEW_MESSAGE" 
          } 
        };
        const tokens = receiverTokens.map(t => t.token);

        const response = await admin.messaging().sendEachForMulticast({ 
          tokens, 
          notification: payload.notification, 
          data: payload.data 
        });
        await Message.updateOne({ _id: msg._id }, { notified: true });

        response.responses.forEach((resp, idx) => {
          if (!resp.success && resp.error?.code === "messaging/registration-token-not-registered") {
            FcmToken.deleteOne({ token: tokens[idx] }).catch(() => {});
          }
        });
      }
    } catch (err) {
      console.error("Errore invio notifica push immediata:", err);
    }
  });

  res.status(201).json(msg);
});

app.post("/fcm/register", verifyUser, async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: "Token FCM mancante" });
  await FcmToken.findOneAndUpdate({ token }, { schoolEmail: req.user.schoolEmail, updatedAt: new Date() }, { upsert: true });
  res.json({ message: "Token FCM salvato" });
});

app.post("/fcm/check-new-messages", verifyAdmin, postLimiterUser, async (req, res) => {
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

app.post("/user/notifications", verifyUser, async (req, res) => {
  const { push, email } = req.body;
  if (push === undefined && email === undefined) return res.status(400).json({ message: "Nessun dato inviato" });
  const update = {};
  if (push !== undefined) update["notifications.push"] = !!push;
  if (email !== undefined) update["notifications.email"] = !!email;
  await User.updateOne({ schoolEmail: req.user.schoolEmail }, update);
  res.json({ message: "Preferenze aggiornate", notifications: update });
});

app.get("/user/notifications", verifyUser, async (req,res) => {
  res.json(req.user.notifications);
});

/* app.post("/create-checkout-session", verifyUser, async (req, res) => {
  const { packageId } = req.body;
  const pkg = CREDIT_PACKAGES[packageId];
  if (!pkg) return res.status(400).json({ message: "Pacchetto non valido" });
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      line_items: [{ price_data: { currency: "eur", product_data: { name: `${pkg.credits} Crediti App Cornaro` }, unit_amount: pkg.price }, quantity: 1 }],
      success_url: `cornaro://success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `cornaro://canceled`,
      metadata: { userEmail: req.user.schoolEmail, packageId },
    });
    res.json({ url: session.url });
  } catch (e) {
    res.status(500).json({ message: "Errore creazione sessione" });
  }
});

app.get("/credits", verifyUser, async (req, res) => {
  res.json({ credits: req.user.credits });
}); */

async function sendEmailViaBridge({ to, subject, text, html }) {
  const fetch = (await import("node-fetch")).default;
  const res = await fetch(process.env.EMAIL_BRIDGE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${process.env.EMAIL_BRIDGE_SECRET}` },
    body: JSON.stringify({ to, subject, text, html })
  });
  if (!res.ok) throw new Error("Errore invio email via bridge");
}

setInterval(()=>{
  const now=Date.now();
  for(const [email,ts] of emailCooldown) if(now-ts>10*60000) emailCooldown.delete(email);
  for(const [email,data] of failedAttempts) if(data.lock<now) failedAttempts.delete(email);
},5*60*1000);

app.listen(PORT);