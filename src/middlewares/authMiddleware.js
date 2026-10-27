// middleware to authenticate JWT tokens

const User = require("../models/User");
const jwt = require("jsonwebtoken");
const authMiddleware = async (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) {
    return res.status(401).json({ message: "Not authorized" });
  }

  const token = header.startsWith("Bearer ") ? header.split(" ")[1] : header;

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }

  try {
    const user = await User.findById(decoded.id).select("role isBanned");
    if (!user) {
      return res.status(401).json({ message: "User no longer exists" });
    }
    if (user.isBanned) {
      return res.status(403).json({ message: "Your account has been banned" });
    }
    req.user = { id: decoded.id, role: user.role }; // role from DB, not from token
  } catch {
    return res.status(500).json({ message: "Authentication failed" });
  }

  next();
};

module.exports = authMiddleware;
