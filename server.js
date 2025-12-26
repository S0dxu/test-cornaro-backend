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
app.use(cors({ origin: "*", methods: ["GET", "POST"], allowedHeaders: ["Content-Type", "Authorization"] }));

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
const requestCache = new Map();

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
  isReliable: { type: Boolean, default: false },
  lastSeenAt: { type: Date, default: null },
  lastSeenUpdateAt: { type: Date, default: null }
});
const User = mongoose.model("User", userSchema);

const codeSchema = new mongoose.Schema({ schoolEmail: { type: String, required: true }, code: String, expiresAt: Date });
const VerificationCode = mongoose.model("VerificationCode", codeSchema);

const infoSchema = new mongoose.Schema({ title: { type: String, required: true }, message: { type: String, required: true }, type: { type: String, enum: ["info","alert"], default: "info" }, createdAt: { type: Date, default: Date.now }, createdBy: String });
const Info = mongoose.model("Info", infoSchema);

const bookSchema = new mongoose.Schema({ title: { type: String, required: true }, condition: { type: String }, price: { type: Number, required: true }, subject: { type: String }, grade: { type: String }, images: [String], likes: { type: Number, default: 0 }, likedBy: [String], createdAt: { type: Date, default: Date.now }, createdBy: String, description: { type: String, maxlength: 1000 }, isbn: { type: String }});
const Book = mongoose.model("Book", bookSchema);

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
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Message = mongoose.model("Message", messageSchema);

function cacheRequest(ttl = 5000) {
  return (req, res, next) => {
    const key = req.originalUrl + JSON.stringify(req.query || {});
    const now = Date.now();
    if (requestCache.has(key)) {
      const { timestamp, data } = requestCache.get(key);
      if (now - timestamp < ttl) return res.json(data);
    }
    const originalJson = res.json.bind(res);
    res.json = (body) => { requestCache.set(key, { timestamp: now, data: body }); originalJson(body); };
    next();
  };
}

function clearInfoCache() { for (const key of requestCache.keys()) if (key.startsWith("/get-info")) requestCache.delete(key); }
function clearBookCache() { for (const key of requestCache.keys()) if (key.startsWith("/get-books")) requestCache.delete(key); }
function clearReviewCache(seller) { for (const key of requestCache.keys()) { if (key.includes(`/reviews/${seller}`)) { requestCache.delete(key); }}}

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
const sendMailWithTimeout = (mailOptions, timeout=10000) => Promise.race([transporter.sendMail(mailOptions), new Promise((_, reject)=>setTimeout(()=>reject(new Error("Timeout invio email")), timeout))]);

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
  res.json({ message:"Login riuscito", token, firstName:user.firstName,lastName:user.lastName,instagram:user.instagram||"",schoolEmail:user.schoolEmail,profileImage:user.profileImage||"" });
});

app.post("/admin/clean-codes", verifyAdmin, async (req,res)=>{ const result=await VerificationCode.deleteMany({ expiresAt:{ $lt:new Date() } }); res.json({ eliminati:result.deletedCount }); });

const storage = multer.memoryStorage();
const upload = multer({ storage, limits:{ fileSize:2*1024*1024 } });

app.post("/upload-imgur", verifyUser, upload.single("image"), async (req,res)=>{
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

app.get("/get-info", cacheRequest(10000), async (req,res)=>{
  let page=parseInt(req.query.page)||1;
  const limit=15;
  const skip=(page-1)*limit;
  const infos = await Info.find({}, { createdBy:0 }).sort({ createdAt:-1 }).skip(skip).limit(limit);
  const total = await Info.countDocuments();
  res.json({ infos,total,page,totalPages:Math.ceil(total/limit) });
});

app.get("/is-admin", verifyUser, async (req,res)=> res.json({ isAdmin:req.user.isAdmin }));

app.get("/get-books", verifyUser, cacheRequest(10000), async (req, res) => {
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

app.post("/add-books", verifyUser, postLimiterUser, async (req, res) => {
  const { title, condition, price, subject, grade, images, description, isbn } = req.body;

  if (!title || !condition || !price || !subject || !grade || !images)
    return res.status(400).json({ message: "Tutti i campi obbligatori devono essere compilati" });

  try {
    for (const imgUrl of images) {
      const nudityCheck = await checkNudity(imgUrl);
      if (nudityCheck.nsfw || nudityCheck.nudity) {
        return res.status(400).json({ message: "Una o più immagini contengono nudità o contenuti non consentiti" });
      }
    }

    const newBook = await Book.create({
      title,
      condition,
      price,
      subject,
      grade,
      images,
      description: description || "",
      isbn: isbn || "",
      likes: 0,
      likedBy: [],
      createdBy: req.user.schoolEmail,
      createdAt: new Date()
    });

    clearBookCache();
    res.status(201).json(newBook);
  } catch (e) {
    res.status(500).json({ message: "Errore server: " + e.message });
  }
});

app.post("/books/like", verifyUser, postLimiterUser, async (req, res) => {
  const { bookId } = req.body;
  if (!bookId) return res.status(400).json({ message: "ID libro mancante" });

  const book = await Book.findById(bookId);
  if (!book) return res.status(404).json({ message: "Libro non trovato" });

  const userEmail = req.user.schoolEmail;
  let likedByMe = false;

  if (book.likedBy.includes(userEmail)) {
    book.likedBy = book.likedBy.filter(email => email !== userEmail);
    book.likes = Math.max(0, book.likes - 1);
  } else {
    book.likedBy.push(userEmail);
    book.likes += 1;
    likedByMe = true;
  }

  await book.save();
  clearBookCache();

  res.json({
    _id: book._id,
    title: book.title,
    likes: book.likes,
    likedByMe,
    images: book.images,
    createdBy: book.createdBy,
    createdAt: book.createdAt
  });
});

app.get("/profile/:email", verifyUser, cacheRequest(10000), async (req, res) => {
  const email = req.params.email;

  const user = await User.findOne(
    { schoolEmail: email },
    {
      firstName: 1,
      lastName: 1,
      profileImage: 1,
      instagram: 1,
      isReliable: 1,
      averageRating: 1,
      ratingsCount: 1,
      lastSeenAt: 1
    }
  ).lean();

  if (!user) return res.status(404).json({ message: "Utente non trovato" });

  const ONLINE_THRESHOLD = 5 * 60 * 1000;

  const isOnline =
    user.lastSeenAt &&
    Date.now() - new Date(user.lastSeenAt).getTime() < ONLINE_THRESHOLD;

  res.status(200).json({
    ...user,
    isOnline,
    isReliable: user.isReliable ?? false
  });
});

app.get("/reviews/:seller", cacheRequest(15000), async (req, res) => {
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
    requestCache.delete(`/profile/${seller}`);

    res.status(201).json({ message: "Recensione inviata" });
  } catch (e) {
    res.status(500).json({ message: "Errore server" });
  }
});

app.post("/chats/start", verifyUser, async (req, res) => {
  const { sellerEmail, bookId } = req.body;

  if (!sellerEmail || !bookId)
    return res.status(400).json({ message: "Dati mancanti" });

  if (sellerEmail === req.user.schoolEmail)
    return res.status(400).json({ message: "Non puoi scrivere a te stesso" });

  if (!bookId) return res.status(400).json({ message: "bookId obbligatorio" });

  let chat = await Chat.findOne({
    seller: sellerEmail,
    buyer: req.user.schoolEmail,
    bookId
  });

  if (chat) {
    return res.status(200).json({
      message: "Chat già esistente",
      chatId: chat._id
    });
  }

  chat = await Chat.create({
    seller: sellerEmail,
    buyer: req.user.schoolEmail,
    bookId
  });

  try {
    const sellerUser = await User.findOne({ schoolEmail: sellerEmail });
    const buyerUser = req.user;
    const book = await Book.findById(bookId);

    if (sellerUser && book) {
      await sendEmailViaBridge({
        to: sellerUser.schoolEmail,
        subject: "Hai una nuova chat su App Cornaro",
        html: `
          <div style="font-family: Arial, sans-serif; background:#f6f6f6; padding:30px;">
            <div style="max-width:600px; margin:auto; background:#fff; padding:20px; border-radius:8px;">
              <h2>Nuovo messaggio ricevuto</h2>

              <p>
                <strong>${buyerUser.firstName} ${buyerUser.lastName}</strong>
                ha iniziato una chat per il libro:
              </p>

              <p style="font-size:18px; font-weight:bold;">
                ${book.title}
              </p>

              <p>
                Apri l’app per rispondere al messaggio.
              </p>
            </div>
          </div>
        `
      });
    }
  } catch (e) {
    console.error("Errore invio email chat:", e.message);
  }

  res.status(201).json({
    message: "Chat creata",
    chatId: chat._id
  });
});

app.get("/chats", verifyUser, async (req, res) => {
  const chats = await Chat.find({
    $or: [
      { seller: req.user.schoolEmail },
      { buyer: req.user.schoolEmail }
    ]
  })
    .sort({ updatedAt: -1 })
    .populate('bookId', 'title images price')
    .lean();

  const mappedChats = chats.map(chat => {
    const me = req.user.schoolEmail;
    const other = chat.seller === me ? chat.buyer : chat.seller;

    const bookInfo = chat.bookId ? {
      title: chat.bookId.title,
      image: chat.bookId.images[0] || null,
      price: chat.bookId.price
    } : null;

    return {
      _id: chat._id,
      me,
      other,
      lastMessage: chat.lastMessage || null,
      updatedAt: chat.updatedAt,
      book: bookInfo
    };
  });

  res.json(mappedChats);
});

app.get("/chats/:chatId/messages", verifyUser, verifyChatAccess, async (req, res) => {
  const { limit = 20, skip = 0 } = req.query;

  if (
    req.chat.lastMessage &&
    req.chat.lastMessage.sender !== req.user.schoolEmail &&
    req.chat.lastMessage.seen === false
  ) {
    await Chat.updateOne(
      { _id: req.chat._id },
      { $set: { "lastMessage.seen": true } }
    );
  }

  const messages = await Message.find({ chatId: req.params.chatId })
    .sort({ createdAt: -1 })
    .skip(parseInt(skip))
    .limit(parseInt(limit))
    .lean();

  const mapped = messages.map(msg => ({
    _id: msg._id,
    sender: msg.sender,
    text: msg.text,
    createdAt: msg.createdAt,
    isMe: msg.sender === req.user.schoolEmail
  }));

  res.json(mapped.reverse());
});


app.post("/chats/:chatId/messages", verifyUser, postLimiterUser, verifyChatAccess, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ message: "Testo mancante" });

  const urlRegex = /(https?:\/\/[^\s]+?\.(?:png|jpg|jpeg|gif|webp))/gi;
  const urls = text.match(urlRegex) || [];

  for (const url of urls) {
    const nudityCheck = await checkNudity(url);
    if (nudityCheck.nsfw || nudityCheck.nudity) {
      return res.status(400).json({ message: "Il messaggio contiene immagini non consentite" });
    }
  }

  const msg = await Message.create({
    chatId: req.params.chatId,
    sender: req.user.schoolEmail,
    text
  });

  await Chat.findByIdAndUpdate(req.params.chatId, {
    lastMessage: {
      text,
      sender: req.user.schoolEmail,
      createdAt: msg.createdAt,
      seen: false
    },
    updatedAt: new Date()
  });

  res.status(201).json(msg);
});

async function sendEmailViaBridge({ to, subject, text, html }) {
  const fetch = (await import("node-fetch")).default;

  const res = await fetch(process.env.EMAIL_BRIDGE_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${process.env.EMAIL_BRIDGE_SECRET}`
    },
    body: JSON.stringify({ to, subject, text, html })
  });

  if (!res.ok) {
    throw new Error("Errore invio email via bridge");
  }
}

setInterval(()=>{
  const now=Date.now();
  for(const [email,ts] of emailCooldown) if(now-ts>10*60000) emailCooldown.delete(email);
  for(const [email,data] of failedAttempts) if(data.lock<now) failedAttempts.delete(email);
},5*60*1000);

app.listen(PORT);