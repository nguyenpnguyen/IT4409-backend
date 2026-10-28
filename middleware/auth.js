const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { fail } = require("../utils/http");

// Xác thực: đọc Bearer token, kiểm tra chữ ký, nạp user và quyền hiệu lực
async function authenticate(req, res, next) {
  const match = (req.get("Authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!match)
    return fail(
      res,
      401,
      "UNAUTHENTICATED",
      "Thiếu access token. Gửi header Authorization: Bearer <token>.",
    );
  let payload;
  try {
    payload = jwt.verify(match[1], process.env.JWT_SECRET);
  } catch (err) {
    return err.name === "TokenExpiredError"
      ? fail(
          res,
          401,
          "TOKEN_EXPIRED",
          "Access token đã hết hạn. Vui lòng đăng nhập lại.",
        )
      : fail(res, 401, "INVALID_TOKEN", "Access token không hợp lệ.");
  }
  const user = await User.findById(payload.sub).populate("roles");
  if (!user || user.status !== "active")
    return fail(
      res,
      401,
      "INVALID_TOKEN",
      "Phiên đăng nhập không còn hiệu lực.",
    );
  // Quyền hiệu lực = HỢP các permission của mọi role, tra lại ở MỖI request (BR-07)
  req.user = user;
  req.permissions = new Set(user.roles.flatMap((r) => r.permissions));
  next();
}

// Phân quyền: endpoint khai báo PERMISSION cần có, không so sánh tên role
function requirePermission(...codes) {
  return (req, res, next) => {
    const missing = codes.filter((c) => !req.permissions.has(c));
    if (missing.length)
      return fail(
        res,
        403,
        "FORBIDDEN",
        `Bạn không có quyền thực hiện thao tác này (cần: ${missing.join(", ")}).`,
      );
    next();
  };
}

module.exports = { authenticate, requirePermission };
