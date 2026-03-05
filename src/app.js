require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const stripe = require("./config/stripe");
const { PORT, MONGO_URI } = require("./config/env");
const { globalLimiter } = require("./middlewares/rateLimit");
const errorHandler = require("./middlewares/errorHandler");

mongoose.connect(process.env.MONGO_URI);

const app = express();

app.use(cors({ 
  origin: "*", 
  methods: ["GET", "POST"], 
  allowedHeaders: ["Content-Type", "Authorization", "stripe-signature"] 
}));
app.use(globalLimiter);
app.use(express.json());

app.post("/stripe-webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const sig = req.headers["stripe-signature"];
      const event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );

      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        await require("./services/webhook")(session);
      }

      res.json({ received: true });
    } catch {
      res.status(400).send("Webhook Error");
    }
  }
);

app.use(errorHandler);

module.exports = app;