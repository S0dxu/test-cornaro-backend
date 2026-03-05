const express = require("express");
const { verifyUser, postLimiterUser, verifyChatAccess, postLimiterIP } = require("../middlewares/auth");
const Chat = require("../models/Chat");
const Message = require("../models/Message");
const router = express.Router();
const multer = require("multer");
const { encrypt, decrypt } = require("../services/encryption");
const { checkNudity } = require("../services/nsfw");
const { sendEmailViaBridge } = require("../services/email");
const FcmToken = require("../models/FcmToken");
const User = require("../models/User");
const Book = require("../models/Book");
const admin = require("firebase-admin");
const IMGUR_REGEX = /https:\/\/i\.imgur\.com\/\S+\.(?:png|jpg|jpeg|gif)/i;

const storage = multer.memoryStorage();
const upload = multer({ storage, limits:{ fileSize:2*1024*1024 } });

router.post("/chats/start", verifyUser, async (req, res) => {
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

router.get("/chats", verifyUser, async (req, res) => {
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

router.get("/chats/:chatId/messages", verifyUser, verifyChatAccess, async (req, res) => {
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

router.post("/chats/:chatId/messages", verifyUser, postLimiterUser, verifyChatAccess, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ message: "Testo mancante" });

  const match = text.match(IMGUR_REGEX);
  if (match) {
    const nudityCheck = await checkNudity(match[0]);
    if (nudityCheck.nsfw || nudityCheck.nudity) {
      return res.status(400).json({ message: "Immagine non consentita" });
    }
  }

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
            title: `${decrypt(req.user.firstName)} ${decrypt(req.user.lastName)}`,
            body: (() => {
              const cleanedText = text.replace(IMGUR_REGEX, "").trim();
              if (!cleanedText) return "📷 Foto";
              return cleanedText.length > 80
                ? cleanedText.slice(0, 80) + "..."
                : cleanedText;
            })()
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

router.post("/upload-imgur", postLimiterIP, upload.single("image"), async (req, res) => {
    if (!req.file)
      return res
        .status(400)
        .json({ message: "File mancante" });

    try {
      const fetch = (await import("node-fetch"))
        .default;

      let nsfwBlocked = false;

      try {
        const boundary =
          "----WebKitFormBoundaryCheckNSFW";

        const body = Buffer.concat([
          Buffer.from(`--${boundary}\r\n`),
          Buffer.from(
            `Content-Disposition: form-data; name="nudepic"; filename="${req.file.originalname}"\r\n`
          ),
          Buffer.from(
            `Content-Type: ${req.file.mimetype}\r\n\r\n`
          ),
          req.file.buffer,
          Buffer.from(
            `\r\n--${boundary}--\r\n`
          ),
        ]);

        const controller =
          new AbortController();

        const timeout = setTimeout(
          () => controller.abort(),
          5000
        );

        const nsfwResponse =
          await fetch(
            "https://letspurify.askjitendra.com/send/data",
            {
              method: "POST",
              headers: {
                accept: "*/*",
                "content-type": `multipart/form-data; boundary=${boundary}`,
              },
              body,
              signal: controller.signal,
            }
          );

        clearTimeout(timeout);

        if (nsfwResponse.ok) {
          const nsfwData =
            await nsfwResponse.json();

          if (nsfwData?.status === true) {
            nsfwBlocked = true;
          }
        }
      } catch (_) {}

      if (nsfwBlocked) {
        return res.status(400).json({
          message:
            "L'immagine non è consentita",
        });
      }

      const base64Image =
        req.file.buffer.toString("base64");

      const imgurResponse =
        await fetch(
          "https://api.imgur.com/3/upload",
          {
            method: "POST",
            headers: {
              Authorization: `Client-ID ${process.env.IMGUR_CLIENT_ID}`,
            },
            body: new URLSearchParams({
              image: base64Image,
            }),
          }
        );

      const imgurData =
        await imgurResponse.json();

      if (imgurData.success) {
        res.json({
          link: imgurData.data.link,
        });
      } else {
        res.status(500).json({
          message:
            "Errore caricamento Imgur",
        });
      }
    } catch (e) {
      res.status(500).json({
        message: e.message,
      });
    }
  }
);

module.exports = router;