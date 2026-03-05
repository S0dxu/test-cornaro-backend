module.exports = (err, req, res, next) => {
  console.error(err);
  if (err.code === 11000) {
    return res.status(400).json({ message: "Duplicate key" });
  }
  res.status(500).json({ message: "Internal Server Error" });
};