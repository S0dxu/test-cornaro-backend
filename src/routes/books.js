const express = require("express");
const { verifyUser, postLimiterUser } = require("../middlewares/auth");
const Book = require("../models/Book");
const User = require("../models/User");
const { checkNudity } = require("../services/nsfw");
const mongoose = require("mongoose");
const { clearBookCache } = require("../services/cache");
const CREDITS_ENABLED = false;
const router = express.Router();

router.get("/get-books", verifyUser, postLimiterUser, async (req, res) => {
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
      createdByMe: book.createdBy === req.user.schoolEmail ? true : false,
      createdAt: book.createdAt,
      description: book.description || "",
      isbn: book.isbn || "",  
    }));

    res.json({ books: booksWithLikes, total, page: currentPage, totalPages: Math.ceil(total / booksLimit) });
  } catch (e) {
    res.status(500).json({ message: "Errore caricamento libri" });
  }
});

router.post("/delete-book", verifyUser, postLimiterUser, async (req, res) => {
  try {
    const { bookId } = req.body;

    if (!bookId) {
      return res.status(400).json({ message: "bookId mancante" });
    }

    const book = await Book.findById(bookId);

    if (!book) {
      return res.status(404).json({ message: "Libro non trovato" });
    }

    if (book.createdBy !== req.user.schoolEmail) {
      return res.status(403).json({ message: "Non autorizzato a eliminare questo libro" });
    }

    await Book.findByIdAndDelete(bookId);

    res.status(200).json({ message: "Libro eliminato correttamente" });
  } catch (error) {
    console.error("Errore eliminazione libro:", error);
    res.status(500).json({ message: "Errore server durante l'eliminazione del libro" });
  }
});

router.get("/get-favorite-books", verifyUser, postLimiterUser, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    const totalBooks = await Book.countDocuments({
      likedBy: req.user.schoolEmail
    });

    const books = await Book.find({
      likedBy: req.user.schoolEmail
    })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

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

    res.json({
      books: result,
      currentPage: page,
      totalPages: Math.ceil(totalBooks / limit)
    });
  } catch (e) {
    res.status(500).json({ message: "Errore caricamento preferiti" });
  }
});

router.post("/add-books", verifyUser, postLimiterUser, async (req, res) => {
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

router.post("/books/like", verifyUser, postLimiterUser, async (req, res) => {
  const { bookId } = req.body;
  const userEmail = req.user.schoolEmail;

  if (!bookId) return res.status(400).json({ message: "bookId mancante" });

  if (!mongoose.Types.ObjectId.isValid(bookId)) {
    return res.status(400).json({ message: "bookId non valido" });
  }

  try {
    const liked = await Book.findOneAndUpdate(
      { _id: bookId, likedBy: { $ne: userEmail } },
      { $addToSet: { likedBy: userEmail }, $inc: { likes: 1 } },
      { new: true, useFindAndModify: false }
    );

    if (liked) {
      liked.likes = liked.likes || 0; // assicura che likes sia un numero
      clearBookCache();
      return res.json({ liked: true, likes: liked.likes });
    }

    const unliked = await Book.findOneAndUpdate(
      { _id: bookId, likedBy: userEmail },
      { $pull: { likedBy: userEmail }, $inc: { likes: -1 } },
      { new: true, useFindAndModify: false }
    );

    if (!unliked) return res.status(404).json({ message: "Libro non trovato" });

    unliked.likes = unliked.likes || 0;
    clearBookCache();
    return res.json({ liked: false, likes: unliked.likes });

  } catch (e) {
    console.error("Errore like:", e);
    res.status(500).json({ message: "Errore server durante il like" });
  }
});

module.exports = router;