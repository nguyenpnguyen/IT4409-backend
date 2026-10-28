const Role = require("../models/Role");
const User = require("../models/User");

// Những quyền trong danh sách mà người gọi KHÔNG có (dùng chống leo thang đặc quyền)
const missingPermissions = (codes, myPermissions) =>
  [...new Set(codes)].filter((c) => !myPermissions.has(c));

// user có phải super-admin active cuối cùng không
async function isLastSuperAdmin(user) {
  const sa = await Role.findOne({ code: "super-admin" });
  if (!sa || !user.roles.some((r) => String(r._id || r) === String(sa._id)))
    return false;
  const others = await User.countDocuments({
    _id: { $ne: user._id },
    status: "active",
    roles: sa._id,
  });
  return others === 0;
}
module.exports = { missingPermissions, isLastSuperAdmin };
