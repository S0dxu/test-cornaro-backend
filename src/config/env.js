require("dotenv").config();

const required = [
  "MONGO_URI",
  "SECRET_KEY",
  "DATA_ENCRYPTION_KEY",
  "STRIPE_SECRET_KEY",
  "STRIPE_WEBHOOK_SECRET",
  "REDIS_URL",
  "FIREBASE_PROJECT_ID",
  "FIREBASE_CLIENT_EMAIL",
  "FIREBASE_PRIVATE_KEY"
];

required.forEach(k => {
  if (!process.env[k]) {
    throw new Error(`Missing env: ${k}`);
  }
});

const ENC_KEY = Buffer.from(process.env.DATA_ENCRYPTION_KEY, "hex");
if (ENC_KEY.length !== 32) {
  throw new Error("DATA_ENCRYPTION_KEY must be 32 bytes hex");
}

module.exports = {
  PORT: process.env.PORT,
  MONGO_URI: process.env.MONGO_URI,
  SECRET_KEY: process.env.SECRET_KEY,
  ENC_KEY,
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET,
  REDIS_URL: process.env.REDIS_URL,
  FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL: process.env.FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY: process.env.FIREBASE_PRIVATE_KEY
};