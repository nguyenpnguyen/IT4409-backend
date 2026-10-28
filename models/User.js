const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, "Email không được để trống"],
      unique: true,
      trim: true,
      lowercase: true,
      match: [/^\S+@\S+\.\S+$/, "Email không đúng định dạng"],
    },
    fullName: {
      type: String,
      required: [true, "Họ tên không được để trống"],
      trim: true,
      minlength: [2, "Họ tên phải có ít nhất 2 ký tự"],
      maxlength: [100, "Họ tên tối đa 100 ký tự"],
    },
    phone: {
      type: String,
      default: null,
      match: [
        /^\+[1-9]\d{7,14}$/,
        "Số điện thoại theo định dạng E.164, ví dụ +84912345678",
      ],
    },
    passwordHash: { type: String, required: true, select: false }, // không bao giờ trả ra ngoài
    status: {
      type: String,
      enum: ["active", "locked", "deleted"],
      default: "active",
    },
    roles: [{ type: mongoose.Schema.Types.ObjectId, ref: "Role" }], // quan hệ n:n User–Role
    lastLoginAt: { type: Date, default: null },
  },
  { timestamps: true },
);

module.exports = mongoose.model("User", userSchema);
