require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const { fail, detail } = require("./utils/http");

const app = express();
// CORS: chỉ cho phép các origin trong danh sách trắng (KHÔNG dùng cors() mở cho mọi origin)
//
const allowed = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin || allowed.includes(origin)),
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Authorization", "Content-Type"],
    exposedHeaders: ["Location"],
  }),
);

app.use(express.json({ limit: "100kb" }));
// Routes
app.use("/api/v1", require("./routes/auth")); // /auth/tokens, /me
app.use("/api/v1/users", require("./routes/users"));
app.use("/api/v1/roles", require("./routes/roles"));
app.use("/api/v1/permissions", require("./routes/permissions"));
// 404 cho endpoint không tồn tại
app.use((req, res) =>
  fail(
    res,
    404,
    "ENDPOINT_NOT_FOUND",
    `Không có endpoint ${req.method} ${req.path}.`,
  ),
);

// Error handler chung
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed")
    return fail(res, 400, "MALFORMED_JSON", "Body không phải JSON hợp lệ.");
  if (err.name === "ValidationError") {
    const details = Object.values(err.errors).map((e) =>
      detail(
        e.path,
        e.kind === "required" ? "REQUIRED" : "INVALID_VALUE",
        e.message,
      ),
    );
    return fail(
      res,
      400,
      "VALIDATION_ERROR",
      "Dữ liệu đầu vào không hợp lệ.",
      details,
    );
  }
  if (err.code === 11000) {
    // TODO: xác định trường bị trùng từ err.keyPattern -> EMAIL_ALREADY_EXISTS /
    ROLE_CODE_EXISTS;
    return fail(res, 409, "CONFLICT", "Dữ liệu bị trùng.");
  }
  console.error(err); // chi tiết chỉ ghi log phía server
  fail(
    res,
    500,
    "INTERNAL_ERROR",
    "Đã có lỗi phía server. Vui lòng thử lại sau.",
  );
});

const PORT = Number(process.env.PORT || 3001);
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("Connected to MongoDB");
    app.listen(PORT, () =>
      console.log(`Server running on http://localhost:${PORT}`),
    );
  })
  .catch((err) => {
    console.error("MongoDB Error:", err.message);
    process.exit(1);
  });
