const User = require("../models/User");
const redis = require("../config/redis");

module.exports = async function(session) {
  const idempotencyKey = `stripe:${session.id}`;
  const exists = await redis.get(idempotencyKey);
  if (exists) return;

  const email = session.customer_email;
  const user = await User.findOne({ schoolEmail: email });
  if (!user) return;

  const premiumUntil = new Date();
  premiumUntil.setMonth(premiumUntil.getMonth() + 1);

  user.premiumUntil = premiumUntil;
  await user.save();

  await redis.set(idempotencyKey, "1", { EX: 86400 });
};