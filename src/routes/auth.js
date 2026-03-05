const express = require("express");
const { postLimiterIP, verifyAdmin } = require("../middlewares/auth");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { checkNudity } = require("../services/nsfw");
const { sendEmailViaBridge } = require("../services/email");
const VerificationCode = require("../models/VerificationCode");
const { SECRET_KEY } = require("../config/env"); 
const router = express.Router();
const emailCooldown = new Map();
const failedAttempts = new Map();
const { decrypt } = require("../services/encryption");

function generateCode(){ const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; let c=""; for(let i=0;i<6;i++) c+=chars[Math.floor(Math.random()*chars.length)]; return c; }
function isValidSchoolEmail(email){ email=email.normalize("NFKC").replace(/[^\x00-\x7F]/g,"").toLowerCase().trim(); if(/[\r\n]/.test(email)) return false; return /^[^@]+@studenti\.liceocornaro\.edu\.it$/.test(email); }

router.post("/register/request", postLimiterIP, async (req,res)=>{
  const { schoolEmail } = req.body;
  if(!schoolEmail) return res.status(400).json({ message: "Email richiesta" });
  if(!isValidSchoolEmail(schoolEmail)) return res.status(400).json({ message: "Email non valida" });
  const existingUser = await User.findOne({ schoolEmail });

  if (existingUser && existingUser.active) {
      return res.status(400).json({ message: "Utente già registrato" });
  }
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

router.post("/register/verify", postLimiterIP, async (req, res) => {
  const { firstName, lastName, instagram, schoolEmail, password, code, profileImage } = req.body;
  if (!firstName || !lastName || !schoolEmail || !password || !code) 
    return res.status(400).json({ message: "Campi obbligatori mancanti" });

  const key = schoolEmail;
  const fail = failedAttempts.get(key) || { count: 0, lock: 0 };
  if (fail.lock > Date.now()) 
    return res.status(429).json({ message: "Bloccato temporaneamente" });

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

  if (record.expiresAt < new Date()) 
    return res.status(400).json({ message: "Codice scaduto" });

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
  const existingUser = await User.findOne({ schoolEmail });

  if (existingUser && existingUser.active) 
    return res.status(400).json({ message: "Utente già esistente" });

  if (existingUser && !existingUser.active) {
    await User.updateOne(
      { _id: existingUser._id },
      { firstName, lastName, instagram: instagram || "", password: hashed, profileImage: validProfileImage, active: true }
    );
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

router.post("/login", postLimiterIP, async (req,res)=>{
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

router.post("/admin/clean-codes", verifyAdmin, async (req,res)=>{ 
    const result = await VerificationCode.deleteMany({ expiresAt:{ $lt:new Date() } }); res.json({ eliminati:result.deletedCount }); 
});

module.exports = router;