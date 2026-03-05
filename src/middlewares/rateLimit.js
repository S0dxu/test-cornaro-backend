const rateLimit = require("express-rate-limit");
const { RedisStore } = require("rate-limit-redis");
const redis = require("../config/redis");

function createLimiter(max, windowMs) {
  return rateLimit({
    store: new RedisStore({
      sendCommand: (...args) => redis.sendCommand(args)
    }),
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false
  });
}

module.exports = {
  globalLimiter: createLimiter(200, 60 * 1000),
  authLimiter: createLimiter(20, 60 * 1000),
  writeLimiter: createLimiter(60, 60 * 1000)
};