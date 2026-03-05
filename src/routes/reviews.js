const express = require("express");
const Review = require("../models/Review");
const { postLimiterUser, verifyUser } = require("../middlewares/auth");
const router = express.Router();
const User = require("../models/User");
const { clearReviewCache } = require("../services/cache");

function isValidSchoolEmail(email){ email=email.normalize("NFKC").replace(/[^\x00-\x7F]/g,"").toLowerCase().trim(); if(/[\r\n]/.test(email)) return false; return /^[^@]+@studenti\.liceocornaro\.edu\.it$/.test(email); }

router.get("/reviews/:seller", postLimiterUser, async (req, res) => {
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

router.post("/reviews/add", verifyUser, postLimiterUser, async (req, res) => {
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

module.exports = router;