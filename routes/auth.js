const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("../models/User");

const { authenticate } = require("../middleware/auth");
const { fail, detail, userView } = require("../utils/http");
const router = express.Router();
const ACCESS_TTL = Number(process.env.ACCESS_TOKEN_TTL || 3600);

router.post("/auth/tokens", async (req, res) => {
  const { grantType, email, password } = req.body || {};
  const details = [];
  if (grantType !== "password")
    details.push(
      detail("grantType", "UNSUPPORTED", "grantType phải là 'password'."),
    );
  if (!email) details.push(detail("email", "REQUIRED", "Thiếu email."));
  if (!password)
    details.push(detail("password", "REQUIRED", "Thiếu mật khẩu."));
  if (details.length)
    return fail(
      res,
      400,
      "VALIDATION_ERROR",
      "Dữ liệu đầu vào không hợp lệ.",
      details,
    );
  const user = await User.findOne({
    email: String(email).trim().toLowerCase(),
    status: { $ne: "deleted" },
  }).select("+passwordHash");
  const ok =
    user && (await bcrypt.compare(String(password), user.passwordHash));
  if (!ok)
    return fail(
      res,
      401,
      "INVALID_CREDENTIALS",
      "Email hoặc mật khẩu không đúng.",
    );
  // TODO: tài khoản locked -> 403 ACCOUNT_LOCKED
  user.lastLoginAt = new Date();
  await user.save();
  const accessToken = jwt.sign(
    { sub: String(user._id) },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TTL },
  );
  res.set("Cache-Control", "no-store");
  res.json({ tokenType: "Bearer", accessToken, expiresIn: ACCESS_TTL });
});

router.get("/me", authenticate, (req, res) => {
  res.json({ ...userView(req.user), permissions: [...req.permissions].sort() });
});

module.exports = router;
