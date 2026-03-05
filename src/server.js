require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const { PORT, MONGO_URI } = require("./config/env");

const app = express();

mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => {
    console.error("MongoDB connection failed:", err);
    process.exit(1);
  });

app.use(cors({ origin: "*", methods: ["GET", "POST"], allowedHeaders: ["Content-Type", "Authorization", "stripe-signature"] }));
app.use(express.json());

const authRoutes = require("./routes/auth");
const bookRoutes = require("./routes/books");
const chatRoutes = require("./routes/chats");
const fcmRoutes = require("./routes/fcm");
const infoRoutes = require("./routes/info");
const premiumRoutes = require("./routes/premium");
const reviewRoutes = require("./routes/reviews");
const profileRoutes = require("./routes/user");

app.use("/", authRoutes);
app.use("/", bookRoutes);
app.use("/", chatRoutes);
app.use("/", fcmRoutes);
app.use("/", infoRoutes);
app.use("/", premiumRoutes);
app.use("/", reviewRoutes);
app.use("/", profileRoutes);

app.get("/", (req, res) => {
  res.send("Server running");
});

const errorHandler = require("./middlewares/errorHandler");
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});

module.exports = app;