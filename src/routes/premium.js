const express = require("express");
const { verifyUser } = require("../middlewares/auth");
const router = express.Router();
const stripe = require("../config/stripe");

router.get("/user/premium", verifyUser, (req, res) => {
  const now = new Date();

  const isPremium =
    req.user.premiumUntil &&
    req.user.premiumUntil instanceof Date &&
    req.user.premiumUntil > now;

  res.json({
    premium: isPremium,
    premiumUntil: req.user.premiumUntil
  });
});

router.post("/premium/create-checkout", verifyUser, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      line_items: [
        {
          price_data: {
            currency: "eur",
            unit_amount: 199,
            product_data: {
              name: "Premium App Cornaro",
              description: "Accesso premium valido 12 mesi"
            }
          },
          quantity: 1
        }
      ],
      success_url: `cornaro://premium-success`,
      cancel_url: `cornaro://premium-cancel`,
      metadata: {
        userEmail: req.user.schoolEmail,
        type: "PREMIUM_YEARLY"
      }
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Errore creazione checkout premium" });
  }
});

module.exports = router;