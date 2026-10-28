const mongoose = require("mongoose");
const permissionSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true }, // "users:read"
  resource: { type: String, required: true }, // "users"
  action: { type: String, required: true }, // "read"
  description: { type: String, default: "" },
});
module.exports = mongoose.model("Permission", permissionSchema);
