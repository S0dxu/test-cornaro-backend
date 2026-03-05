const { createClient } = require("redis");

const redisClient = createClient({ url: process.env.REDIS_URL });

redisClient.on("error", (err) => {
  console.error("Redis error:", err);
});

(async () => {
  try {
    await redisClient.connect();
    console.log("Redis connected");
  } catch (err) {
    console.error("Redis connection failed:", err);
  }
})();

module.exports = redisClient;