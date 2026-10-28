const mongoose = require("mongoose");

const roleSchema = new mongoose.Schema(
  {
    code: {
      type: String,
      required: [true, "Mã role không được để trống"],
      unique: true,
      trim: true,
      match: [
        /^[a-z][a-z0-9-]{2,49}$/,
        "Mã role: chữ thường, số, gạch nối; 3–50 ký tự; bắt đầu bằng chữ",
      ],
      immutable: true, // không đổi sau khi tạo
    },
    name: {
      type: String,
      required: [true, "Tên role không được để trống"],
      trim: true,
      minlength: [2, "Tên role phải có ít nhất 2 ký tự"],
      maxlength: [100, "Tên role tối đa 100 ký tự"],
    },
    description: { type: String, default: null },
    isSystem: { type: Boolean, default: false, immutable: true },
    permissions: { type: [String], default: [] },
  },
  { timestamps: true },
);

module.exports = mongoose.model("Role", roleSchema);
